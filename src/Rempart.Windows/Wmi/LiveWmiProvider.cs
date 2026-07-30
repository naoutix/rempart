using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using Rempart.Core.Providers;

namespace Rempart.Windows.Wmi;

/// <summary>
/// WMI client built on COM interop generated at compile time.
///
/// Answers the question left open since M0: <c>System.Management</c> does not
/// survive Native AOT, but WMI stays reachable by going straight to its COM
/// interfaces. No reflection at runtime, hence no trim warning and no surprise
/// after publishing.
///
/// Most of the namespaces we target require elevation. A refusal maps to
/// <see cref="ReadStatus.AccessDenied"/>, which the engine renders as
/// « non vérifiable »: the scan could not look, the machine is not at fault.
/// A failure is not a refusal and does not get to look like one — see
/// <see cref="Classify"/>.
///
/// Nor does an enumeration get to run for ever: WMI is the one surface here whose answer
/// comes from third-party code — every product that installs a WMI provider adds one — and
/// it is queried with a budget, like DISM and netsh. See <see cref="Drain"/>.
/// </summary>
public sealed unsafe partial class LiveWmiProvider(TimeSpan? timeout = null) : IWmiProvider
{
    private static readonly Guid ClsidWbemLocator = new("4590f811-1d3a-11d0-891f-00aa004b2e24");
    private static readonly Guid IidWbemLocator = new("dc12a687-737f-11cf-884d-00aa004b2e24");

    private const int WbemFlagForwardOnly = 0x20;
    private const int WbemFlagReturnImmediately = 0x10;

    /// <summary>
    /// <c>WBEM_S_TIMEDOUT</c>, from <c>WbemCli.h</c>. A <c>WBEM_S_</c> code: the deadline
    /// arrives as a <em>success</em>, which is what let it pass for the end of the
    /// enumeration.
    /// </summary>
    private const int WbemSTimedout = 0x40004;

    private const int RpcCAuthnLevelDefault = 0;
    private const int RpcCImpLevelImpersonate = 3;
    private const int EoacNone = 0;

    // Named rather than inlined: a bare hexadecimal literal cannot be reviewed, and these
    // codes sit one digit apart from unrelated ones — 0x80041062 is the privilege refusal,
    // 0x80041045 is WBEM_E_SERVER_TOO_BUSY, which must never advise elevation. Values read
    // from wbemcli.h and winerror.h, not from memory.
    private const uint WbemENotFound = 0x80041002;
    private const uint WbemEAccessDenied = 0x80041003;
    private const uint WbemEInvalidNamespace = 0x8004100E;
    private const uint WbemEPrivilegeNotHeld = 0x80041062;
    private const uint EAccessDenied = 0x80070005;

    /// <summary>
    /// <c>WBEM_E_INVALID_CLASS</c>. The one code in this file established by measurement
    /// rather than by reading a header: querying a class that does not exist returns it on
    /// the first <c>Next</c>, so it is what a Windows edition lacking a feature answers.
    /// It was classified as a damaged repository, which is plausible and is not what the
    /// machine does — see <see cref="Classify"/>.
    /// </summary>
    private const uint WbemEInvalidClass = 0x80041010;

    /// <summary>
    /// How long one enumeration may take. Generous on purpose — a healthy machine answers
    /// <c>Win32_Process</c> in a few milliseconds, and this ceiling exists to end a wedged
    /// provider, not to race a slow one. Injectable so a test can shorten it.
    /// </summary>
    private readonly TimeSpan budget = timeout ?? TimeSpan.FromSeconds(30);

    [LibraryImport("ole32.dll")]
    private static partial int CoInitializeSecurity(
        IntPtr descriptor, int authServices, IntPtr services, IntPtr reserved1,
        int authnLevel, int impLevel, IntPtr authList, int capabilities, IntPtr reserved3);

    [LibraryImport("ole32.dll")]
    private static partial int CoSetProxyBlanket(
        IntPtr proxy, int authnService, int authzService, IntPtr principalName,
        int authnLevel, int impLevel, IntPtr authInfo, int capabilities);

    /// <summary>
    /// COM security initialisation only counts once per process, and failing a
    /// second time is normal — hence the ignored result.
    /// </summary>
    private static readonly bool SecurityInitialised = InitialiseSecurity();

    private static bool InitialiseSecurity()
    {
        CoInitializeSecurity(
            IntPtr.Zero, -1, IntPtr.Zero, IntPtr.Zero,
            RpcCAuthnLevelDefault, RpcCImpLevelImpersonate, IntPtr.Zero, EoacNone, IntPtr.Zero);
        return true;
    }

    [LibraryImport("oleaut32.dll")]
    private static partial int VariantClear(ref Variant value);

    [LibraryImport("ole32.dll")]
    private static partial int CoCreateInstance(
        in Guid clsid, IntPtr outer, int context, in Guid iid, out IntPtr instance);

    public WmiRead Query(string namespacePath, string className, IReadOnlyList<string> properties)
    {
        _ = SecurityInitialised;

        try
        {
            return Execute(namespacePath, className, properties);
        }
        catch (COMException ex)
        {
            return Classify(ex);
        }
        catch (Exception ex)
        {
            // A failure must not interrupt the scan, but neither must it disguise
            // itself as an access denial: that confusion is what once led to the
            // wrong conclusion that elevation would be enough.
            return WmiRead.Failed($"{ex.GetType().Name} : {ex.Message}");
        }
    }

    /// <summary>
    /// Turns a COM failure into a read status.
    ///
    /// <para>
    /// The list used to end on <c>_ => WmiRead.AccessDenied</c>, so every HRESULT nobody had
    /// thought of borrowed the meaning « relancer en administrateur ». A WMI stack that fails
    /// to initialise (<c>WBEM_E_INITIALIZATION_FAILURE</c>) and a Winmgmt service refusing to
    /// start (<c>RPC_S_SERVER_UNAVAILABLE</c>) therefore asked for an elevation the user already
    /// had, on every WMI-backed surface at once — drivers, processes, unquoted service
    /// paths, <c>root\subscription</c> — and <see cref="WmiRead.AccessDenied"/> carries no
    /// diagnostic, so the report had nothing to contradict it with. That is the invariant
    /// this very file documents, broken inside it: the <c>catch (Exception)</c> below
    /// refused the disguise the arm above it applied.
    /// </para>
    ///
    /// <para>
    /// Hence the shape rather than the entries: what is enumerated is only what a code
    /// genuinely means, and the default arm is the honest one. A HRESULT left off the list
    /// now surfaces as a failure carrying its own code — the user has something to search
    /// for, and this mapping cannot silently rot as WMI grows new ways to fail.
    /// </para>
    ///
    /// <para>
    /// <b>And it is the only such mapping in this file.</b> <see cref="Drain"/> used to hold a
    /// second, unwritten one — every failure arriving before the first object was an absence,
    /// whatever the code — which contradicted this one on the path that is actually reached.
    /// Two tables cannot be kept in step by remembering to, so there is one, and the exit that
    /// had the other now asks it. That is also why the overload below takes a bare HRESULT:
    /// the walk has no <see cref="COMException"/> to hand over, only the code and the class it
    /// was reading.
    /// </para>
    /// </summary>
    internal static WmiRead Classify(COMException ex) => Classify(ex.HResult, ex.Message);

    /// <param name="context">
    /// What was being attempted, printed after the code for a caller who has to search for it.
    /// </param>
    /// <inheritdoc cref="Classify(COMException)"/>
    internal static WmiRead Classify(int hresult, string context) => (uint)hresult switch
    {
        // The scan is not elevated, or lacks a privilege the namespace demands: elevation
        // is the answer, and these are the only codes that say so.
        WbemEAccessDenied or EAccessDenied or WbemEPrivilegeNotHeld => WmiRead.AccessDenied,

        // The namespace or the class is not there, which is what a Windows edition lacking
        // the feature answers. Absence, not refusal.
        //
        // WBEM_E_INVALID_CLASS sat on the default arm as « damaged repository » until it was
        // measured: an absent class is what actually produces it, on the first Next, and
        // Drain answered NotFound for it long before this mapping was consulted there. A
        // repository genuinely damaged reports WBEM_E_CRITICAL_ERROR or
        // WBEM_E_INITIALIZATION_FAILURE, both of which stay below.
        WbemEInvalidNamespace or WbemENotFound or WbemEInvalidClass => WmiRead.NotFound,

        _ => WmiRead.Failed($"COM 0x{(uint)hresult:X8} : {context}"),
    };

    private WmiRead Execute(
        string namespacePath, string className, IReadOnlyList<string> properties)
    {
        var locator = CreateLocator();

        if (locator.ConnectServer(namespacePath, null, null, null, 0, null, IntPtr.Zero,
                out var services) is var connect && connect < 0)
        {
            throw new COMException($"ConnectServer({namespacePath})", connect);
        }

        // The blanket specifies the caller's identity. It is only essential for
        // remote connections: locally, CoInitializeSecurity is enough. Its failure
        // must therefore not doom the query.
        TrySetBlanket(services);

        var query = $"SELECT * FROM {className}";
        if (services.ExecQuery("WQL", query, WbemFlagForwardOnly | WbemFlagReturnImmediately,
                IntPtr.Zero, out var enumerator) is var exec && exec < 0)
        {
            throw new COMException(query, exec);
        }

        TrySetBlanket(enumerator);

        return Drain(Next, Read, budget, className);

        int Next(int timeout, IntPtr[] slot, out int returned)
        {
            var hresult = enumerator.Next(timeout, 1, slot, out var count);
            returned = (int)count;

            return hresult;
        }

        WmiInstance? Read(IntPtr pointer)
        {
            var instance = ComInterfaceMarshaller<IWbemClassObject>.ConvertToManaged((void*)pointer);

            try
            {
                return instance is null ? null : ReadProperties(instance, properties);
            }
            finally
            {
                Marshal.Release(pointer);
            }
        }
    }

    /// <summary>One call to <c>IEnumWbemClassObject::Next</c>, asking for a single object.</summary>
    internal delegate int WbemNext(int timeoutMilliseconds, IntPtr[] slot, out int returned);

    /// <summary>
    /// Walks an enumeration to its end, or to the end of its budget.
    ///
    /// <para>
    /// <b>What this replaces.</b> <c>Next</c> was called with <c>WBEM_INFINITE</c>, so a WMI
    /// provider that stopped answering — a wedged third-party provider, a damaged repository
    /// — suspended the scan with no way out and nothing printed. DISM and netsh, the two
    /// other places this project waits on something it does not control, have each carried
    /// an explicit budget since they were written; the two COM enumerations had none, and
    /// they are the ones behind <c>Win32_Process</c>, <c>Win32_SystemDriver</c>, BitLocker
    /// and SecurityCenter2.
    /// </para>
    ///
    /// <para>
    /// <b>The deadline is the enumeration's, not each call's.</b> Handing the whole budget
    /// to every <c>Next</c> would bound one wait and not the walk: a provider yielding one
    /// object just under the ceiling would keep the scan for as long as it liked. So each
    /// call gets what is left.
    /// </para>
    ///
    /// <para>
    /// <b>Running out is a failure, and it says so.</b> Not a refusal — nothing was denied,
    /// so « relancer en administrateur » is the wrong advice — and not an absence, which is
    /// the trap <c>WBEM_S_TIMEDOUT</c> lays: 0x40004 has its sign bit clear, so a loop
    /// testing « the HRESULT is not negative » reads it as success and the zero objects
    /// beside it end the walk. What was collected until then was handed over as
    /// <see cref="ReadStatus.Found"/>: a truncated enumeration presented as a complete one.
    /// </para>
    ///
    /// <para>
    /// <b>Nothing the walk was handed is dropped, whichever way it ends.</b> The exits below
    /// used to disagree about that — a deadline threw away the objects it had, a broken walk
    /// kept them — and the disagreement is the one #153's commit declared rather than settled.
    /// Every exit is now handed <c>instances</c>, save the one reached before anything can
    /// have walked. Checking that off exit by exit is the coverage-by-enumeration this file
    /// has already been caught at, so what a test holds is the property: however the walk
    /// ends — the enumeration finishing, the budget running out, <c>WBEM_S_TIMEDOUT</c>, a
    /// negative HRESULT — the read carries every object the walk was handed.
    /// </para>
    ///
    /// <para>
    /// <b>On one premise, and it is worth writing down because the loop rests on it.</b>
    /// <c>Next</c> is asked for exactly one object at a time — see <see cref="WbemNext"/> —
    /// so a code other than <c>WBEM_S_NO_ERROR</c> arrives with nothing in the slot. The two
    /// tests below return before reading <c>returned</c>, so an object handed over
    /// <em>beside</em> a deadline or a failure would be dropped, and its COM pointer never
    /// released: <c>Marshal.Release</c> only runs inside the read. Scripting that pair proves
    /// it — the walk is handed one object and the read carries none — which is why the
    /// sentence above says « however the walk ends » and not « whatever <c>Next</c> answers ».
    /// A caller that ever asks for more than one object has to move those tests past the slot.
    /// </para>
    ///
    /// <para>
    /// <b>And so is breaking in mid-walk.</b> The sentence above was written about the
    /// deadline and was just as true of the other half of the same condition: a
    /// <em>negative</em> HRESULT — <c>WBEM_E_PROVIDER_FAILURE</c>,
    /// <c>WBEM_E_CALL_CANCELLED</c>, a repository going bad after <c>ExecQuery</c> succeeded
    /// — left the loop by the same door as the end of the enumeration, and the objects
    /// already collected went out as <see cref="ReadStatus.Found"/> with nothing said. Only
    /// <c>WBEM_S_FALSE</c> ends a walk; a failure ends it short, and
    /// <see cref="Interrupted"/> names the code that did it while keeping what arrived.
    /// </para>
    ///
    /// <para>
    /// <b>Which is not the same as a failure on the first call.</b> <c>ExecQuery</c> is asked
    /// with <c>WBEM_FLAG_RETURN_IMMEDIATELY</c>, so it is only semi-synchronous: the query's
    /// own verdict is delivered here, on the first <c>Next</c> — an unknown class arrives as
    /// <c>WBEM_E_INVALID_CLASS</c> at this loop and never at the call that asked for it.
    /// Nothing has been handed over then, so there is no truncated inventory to report, and
    /// the objects kept by the three exits above are not this branch's question.
    /// </para>
    ///
    /// <para>
    /// <b>But the verdict is, and it used to be taken from the position instead of the code.</b>
    /// Every first-call failure became <see cref="WmiRead.NotFound"/> with no diagnostic,
    /// which is right for the absent class and wrong for the rest — and a null diagnostic is
    /// exactly what makes each consumer fall back to its own hard-coded sentence. Measured
    /// rather than reasoned: <c>WBEM_E_PROVIDER_LOAD_FAILURE</c> (0x80041013) left here as an
    /// absence, whereupon <c>LiveDriverProvider</c> supplied « Énumération des pilotes
    /// refusée par WMI. Relancer en administrateur » — elevation prescribed for a provider
    /// that will not load, and no amount of it will make one load.
    /// </para>
    ///
    /// <para>
    /// So the branch asks <see cref="Classify"/>, which is the file's one opinion on what a
    /// HRESULT means and had the right answer all along. Not a list of codes copied down here:
    /// two lists is how the contradiction arose, and the second one would have to be kept in
    /// step by hand. The absent class keeps the answer it had — <c>WBEM_E_INVALID_CLASS</c>
    /// joined the absence arm over there, where it belonged once it had been measured — and a
    /// code nobody has classified surfaces as a failure printing itself, on this path as on
    /// the other.
    /// </para>
    /// </summary>
    internal static WmiRead Drain(
        WbemNext next, Func<IntPtr, WmiInstance?> read, TimeSpan budget, string className)
    {
        var instances = new List<WmiInstance>();
        var slot = new IntPtr[1];
        var started = Stopwatch.GetTimestamp();

        // Whether any object has been handed over yet. It is what separates the query
        // answering late from the walk breaking: see the failure branch below.
        var walking = false;

        while (true)
        {
            var remaining = budget - Stopwatch.GetElapsedTime(started);

            if (remaining <= TimeSpan.Zero)
            {
                return TimedOut(className, budget, instances);
            }

            // At least one millisecond: zero is a poll, and a provider that is merely slow
            // would then be reported as wedged.
            var wait = (int)Math.Clamp(Math.Ceiling(remaining.TotalMilliseconds), 1, int.MaxValue);

            var hresult = next(wait, slot, out var returned);

            if (hresult == WbemSTimedout)
            {
                return TimedOut(className, budget, instances);
            }

            if (hresult < 0)
            {
                // A failure once objects have been handed over cannot be the query's own
                // verdict — that one has already been given. The walk broke, and what it
                // collected is not the machine's inventory: it is said, and kept.
                if (walking)
                {
                    return Interrupted(className, hresult, instances);
                }

                // Nothing walked yet, so this is ExecQuery answering late: with
                // WBEM_FLAG_RETURN_IMMEDIATELY the query is only semi-synchronous, and an
                // unknown class comes back as WBEM_E_INVALID_CLASS here rather than there —
                // measured on this machine, not assumed. What the code means is Classify's
                // question and not this loop's: answering NotFound to all of them was a
                // verdict read off the position, and it made a provider that would not load
                // indistinguishable from a feature Windows does not ship.
                return Classify(
                    hresult,
                    $"la requête WMI sur {className} a échoué avant de rendre le premier objet.");
            }

            // The end of the enumeration, and now the only thing that reaches here:
            // WBEM_S_FALSE with no object, or a success that handed nothing back.
            if (returned != 1)
            {
                break;
            }

            walking = true;

            if (read(slot[0]) is { } instance)
            {
                instances.Add(instance);
            }
        }

        return instances.Count == 0 ? WmiRead.NotFound : WmiRead.Found(instances);
    }

    /// <summary>
    /// What a WMI enumeration that ran out of time answers. Named after the class, because
    /// one wedged provider does not make WMI mute and the report has to say which surface
    /// went quiet.
    ///
    /// <para>
    /// <b>It keeps what the walk had collected.</b> It did not, and that was the last exit of
    /// this loop still throwing an inventory away: <see cref="WmiRead.Failed"/> hands back an
    /// empty list, so a deadline reached after two hundred drivers answered none. #153 gave
    /// the loss a count — « N instance(s) déjà lue(s) sont écartées » — which broke the
    /// silence without undoing the loss, and left this exit disagreeing with
    /// <see cref="Interrupted"/> three lines away.
    /// </para>
    ///
    /// <para>
    /// <b>Why the disagreement resolves this way.</b> The emptiness was never argued for here
    /// — it came with <see cref="WmiRead.Failed"/>, which #143 chose to say « this is a
    /// failure, not a refusal and not an absence ». The one place #143 does argue for
    /// distrusting a truncated walk is its netapi32 half, where the walk yields a
    /// <em>count</em> of accounts that is plausible and false. One consumer of this read does
    /// derive a count — <c>RunningProcessesCollector</c> groups processes by binary and puts
    /// « instances » in the finding's details — so a truncated walk can print « 7 instances de
    /// svchost.exe » where twelve run. It is tolerated, and for reasons that have to be stated
    /// rather than assumed: the count is per binary, not a total the report reasons over; the
    /// same status forces a <c>Finding.Unread</c> onto that same collector, so the figure
    /// never travels without the sentence saying the walk did not finish; and
    /// <see cref="Interrupted"/> has been reaching it that way since #153, so this exit adds
    /// no path that was not already open. The consumer that needs « all of them »,
    /// <c>CheckReader.ReadWmi</c>, keeps nothing on any status but <c>Found</c> whatever this
    /// method hands it. What is left of the case for dropping — a provider that stopped
    /// mid-inventory gives no ground to trust the prefix it delivered — does not survive its
    /// own neighbour: a provider that <em>failed</em> mid-walk is the harder case, and #153
    /// settled that one by keeping, as #135 had for the scheduler and
    /// <c>ListeningPortRead.Partial</c> for the listening tables before it. What arrived here
    /// arrived through a <c>Next</c> that succeeded and was decoded like any other object; the
    /// deadline says the walk did not finish, not that what finished is wrong. And the two
    /// mistakes do not cost the same: every consumer adds its gap finding on the status alone,
    /// so keeping a prefix can only add findings, while dropping it hides the vulnerable
    /// driver that was already in hand.
    /// </para>
    ///
    /// <para>
    /// The status still says the list is not the machine's, so nothing reads it as an
    /// inventory. The count stays in the sentence, since it is what tells a provider mute from
    /// the first call apart from one that stopped after two hundred objects; it is now a claim
    /// about what the reader has rather than about what was taken away. #143's budget is
    /// untouched — this changes what a deadline answers, never when it fires.
    /// </para>
    /// </summary>
    private static WmiRead TimedOut(
        string className, TimeSpan budget, IReadOnlyList<WmiInstance> instances) => WmiRead.Partial(
        instances,
        $"L'énumération WMI de {className} n'a pas répondu en {budget.TotalSeconds:0} s. "
        + "Un fournisseur WMI est peut-être bloqué."
        + (instances.Count == 0
            ? string.Empty
            : $" {instances.Count} instance(s) lue(s) avant l'échéance sont conservées : "
            + "l'inventaire est incomplet."));

    /// <summary>
    /// What a WMI enumeration that broke in mid-walk answers: the objects that did arrive,
    /// and beside them the code that ended the walk and how far it had got.
    ///
    /// <para>
    /// <see cref="WmiRead.Partial"/> and not <see cref="WmiRead.Failed"/>, which would drop
    /// them. Both are the same status — the enum has three members and none of them is
    /// « partial » — so what a consumer has to read is the instance list, and every consumer
    /// of a WMI read was gone over for that.
    /// </para>
    ///
    /// <para>
    /// The HRESULT is printed, not interpreted. <see cref="Classify"/> owns the question of
    /// which codes mean « relancer en administrateur » and answers it for a query that never
    /// started; here the query was accepted — namespace opened, class resolved, objects
    /// already handed over — so a failure arriving afterwards is not a rights problem and
    /// must not be dressed as one. That is the invariant CONTRIBUTING records, and the same
    /// trap #147 found one interface away.
    /// </para>
    /// </summary>
    private static WmiRead Interrupted(
        string className, int hresult, IReadOnlyList<WmiInstance> instances) =>
        WmiRead.Partial(instances,
            $"L'énumération WMI de {className} s'est interrompue sur 0x{(uint)hresult:X8} "
            + $"après {instances.Count} instance(s) : l'inventaire est incomplet.");

    private static WmiInstance ReadProperties(
        IWbemClassObject instance, IReadOnlyList<string> names)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in names)
        {
            var variant = default(Variant);

            if (instance.Get(name, 0, ref variant, IntPtr.Zero, IntPtr.Zero) < 0)
            {
                continue;
            }

            try
            {
                if (Decode(variant) is { } text)
                {
                    values[name] = text;
                }
            }
            finally
            {
                // An unreleased BSTR leaks on every read, hence on every scan.
                VariantClear(ref variant);
            }
        }

        return new WmiInstance(values);
    }

    /// <summary>
    /// Only the types WMI returns for the properties we query. An uncovered type is
    /// ignored rather than rendered approximately: better an absent property, hence
    /// a « non vérifiable » verdict, than a wrong value.
    /// </summary>
    private static string? Decode(Variant variant) => variant.Vt switch
    {
        VariantType.Empty or VariantType.Null => null,

        VariantType.Bstr => Marshal.PtrToStringBSTR(variant.Data),

        VariantType.Bool => ((short)variant.Data.ToInt64()) != 0 ? "true" : "false",

        VariantType.I2 or VariantType.I4 or VariantType.Int =>
            ((int)variant.Data.ToInt64()).ToString(CultureInfo.InvariantCulture),

        VariantType.I1 or VariantType.Ui1 or VariantType.Ui2
            or VariantType.Ui4 or VariantType.Uint =>
            ((uint)variant.Data.ToInt64()).ToString(CultureInfo.InvariantCulture),

        _ => null,
    };

    /// <summary>
    /// <c>Marshal.GetIUnknownForObject</c> requires the runtime's built-in COM
    /// support, absent under Native AOT: there it always throws.
    ///
    /// This is the bug that left WMI dead in the published binary. The exception
    /// bubbled up to the catch-all, translated into "access denied" — so every WMI
    /// check rendered « non vérifiable », even elevated, with nothing to tell this
    /// bug apart from missing rights.
    ///
    /// The query works without a blanket locally: the failure is ignored.
    /// </summary>
    private static void TrySetBlanket(object proxy)
    {
        try
        {
            var pointer = Marshal.GetIUnknownForObject(proxy);
            try
            {
                CoSetProxyBlanket(pointer, 10 /* RPC_C_AUTHN_WINNT */, 0, IntPtr.Zero,
                    RpcCAuthnLevelDefault, RpcCImpLevelImpersonate, IntPtr.Zero, EoacNone);
            }
            finally
            {
                Marshal.Release(pointer);
            }
        }
        catch (Exception)
        {
            // No effect locally: the connection keeps the process identity.
        }
    }

    /// <summary>
    /// Instantiated through CoCreateInstance rather than Type.GetTypeFromCLSID: the
    /// latter goes through reflection and the AOT compiler refuses it. The
    /// IsAotCompatible guard flagged it at compile time, where the problem would
    /// otherwise only have surfaced after publishing.
    /// </summary>
    private static IWbemLocator CreateLocator()
    {
        const int ClsCtxInprocServer = 1;

        var result = CoCreateInstance(
            in ClsidWbemLocator, IntPtr.Zero, ClsCtxInprocServer, in IidWbemLocator, out var pointer);

        if (result < 0 || pointer == IntPtr.Zero)
        {
            throw new COMException("CoCreateInstance(WbemLocator)", result);
        }

        try
        {
            return ComInterfaceMarshaller<IWbemLocator>.ConvertToManaged((void*)pointer)
                ?? throw new COMException("WbemLocator non convertible", -1);
        }
        finally
        {
            Marshal.Release(pointer);
        }
    }
}
