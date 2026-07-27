namespace Rempart.Core.Providers;

/// <summary>
/// What the catalog lookup had to say about a file.
///
/// <para>
/// Named cases rather than the <c>int?</c> this used to be, because that nullable carried
/// two answers under one value and the audit acted on both the same way. <c>null</c> meant
/// « no catalog references this file », which is a finding, <b>and</b> « the catalog store
/// could not be asked », which is a gap — a context <c>CryptCATAdminAcquireContext2</c>
/// refused, a hash that would not compute, a file locked by another process.
/// <c>AuthenticodeVerdict</c> mapped the pair onto <c>Unsigned</c> and
/// <c>SignatureLadder</c> turns <c>Unsigned</c> into a <c>Suspicious</c> finding, so a
/// file the tool could not open came out <b>accused</b> — on exactly the machines that are
/// hardest to audit, where reads fail most. Recorded as DET-CATALOGUE-MUET and fixed here.
/// </para>
///
/// <para>
/// The two cases still look alike from the outside and only the call site can tell them
/// apart, which is why they are separated where the interop happens rather than reasoned
/// about afterwards.
/// </para>
/// </summary>
public enum CatalogOutcome
{
    /// <summary>
    /// The lookup was never run, because the file answered for itself: a valid embedded
    /// signature, or a broken one. The default value on purpose — a caller that forgets to
    /// fill this in gets « nobody looked », never « nothing found ».
    /// </summary>
    NotAsked,

    /// <summary>A catalog covers the file and validates it. This is how <c>cmd.exe</c> is signed.</summary>
    Verified,

    /// <summary>
    /// The store answered, and no catalog references this file. An answer, not a failure:
    /// the file is signed in no way at all.
    /// </summary>
    NotCatalogued,

    /// <summary>A catalog covers the file and refuses it — expired, revoked, or tampered with.</summary>
    Refused,

    /// <summary>
    /// The store could not be asked at all, so nothing is known about this file. Distinct
    /// from <see cref="NotCatalogued"/>, and the whole point of this type: an unreadable
    /// file must be reported as unverifiable, never accused of being unsigned.
    /// </summary>
    Unaskable,
}
