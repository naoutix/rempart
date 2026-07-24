using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace Rempart.Windows.Tasks;

/// <summary>
/// COM interfaces of the Task Scheduler, declared for the interop generator.
///
/// Same approach as for WMI: <c>GeneratedComInterface</c> produces the transition at
/// compile time, without reflection, hence Native AOT compatible.
///
/// <para>
/// One essential difference from WMI: these interfaces derive from <c>IDispatch</c>,
/// not <c>IUnknown</c>. Four additional slots therefore precede them in the
/// virtual table — <c>GetTypeInfoCount</c>, <c>GetTypeInfo</c>,
/// <c>GetIDsOfNames</c>, <c>Invoke</c>. Omitting them would call the wrong function
/// with the wrong arguments: a crash if we are lucky, a wrong result otherwise.
/// </para>
///
/// <para>
/// The method order is taken from <c>taskschd.h</c> in the Windows SDK, not from
/// memory. A single-slot offset is invisible at compile time and is paid for at
/// run time.
/// </para>
/// </summary>
internal static class TaskSchedulerIds
{
    internal static readonly Guid ClsidTaskScheduler =
        new("0f87369f-a4e5-4cfc-bd3e-73e6154572dd");

    internal static readonly Guid IidTaskService =
        new("2faba4c7-4da9-4013-9697-20cc3fd40f85");

    /// <summary>
    /// Includes hidden tasks. An audit that could not see them would miss exactly
    /// the ones someone took care to hide.
    /// </summary>
    internal const int EnumHidden = 1;
}

[GeneratedComInterface]
[Guid("2faba4c7-4da9-4013-9697-20cc3fd40f85")]
internal partial interface ITaskService
{
    // IDispatch slots. Never called, never removed: they are what keeps everything
    // that follows aligned on the right function.
    void GetTypeInfoCount_Unused();

    void GetTypeInfo_Unused();

    void GetIDsOfNames_Unused();

    void Invoke_Unused();

    [PreserveSig]
    int GetFolder(
        [MarshalAs(UnmanagedType.BStr)] string path,
        out ITaskFolder folder);

    void GetRunningTasks_Unused();

    void NewTask_Unused();

    /// <summary>
    /// Four empty VARIANTs designate the local machine and the current user.
    /// The VARIANT is declared as a blittable struct — the generated interop cannot
    /// express it any other way, the same constraint as for WMI.
    /// </summary>
    [PreserveSig]
    int Connect(Wmi.Variant server, Wmi.Variant user, Wmi.Variant domain, Wmi.Variant password);
}

[GeneratedComInterface]
[Guid("8cfac062-a080-4c15-9a88-aa7c2af80dfc")]
internal partial interface ITaskFolder
{
    // IDispatch slots. Never called, never removed: they are what keeps everything
    // that follows aligned on the right function.
    void GetTypeInfoCount_Unused();

    void GetTypeInfo_Unused();

    void GetIDsOfNames_Unused();

    void Invoke_Unused();

    void get_Name_Unused();

    [PreserveSig]
    int get_Path([MarshalAs(UnmanagedType.BStr)] out string path);

    void GetFolder_Unused();

    [PreserveSig]
    int GetFolders(int flags, out ITaskFolderCollection folders);

    void CreateFolder_Unused();

    void DeleteFolder_Unused();

    void GetTask_Unused();

    [PreserveSig]
    int GetTasks(int flags, out IRegisteredTaskCollection tasks);
}

[GeneratedComInterface]
[Guid("79184a66-8664-423f-97f1-637356a5d812")]
internal partial interface ITaskFolderCollection
{
    // IDispatch slots. Never called, never removed: they are what keeps everything
    // that follows aligned on the right function.
    void GetTypeInfoCount_Unused();

    void GetTypeInfo_Unused();

    void GetIDsOfNames_Unused();

    void Invoke_Unused();

    [PreserveSig]
    int get_Count(out int count);

    [PreserveSig]
    int get_Item(Wmi.Variant index, out ITaskFolder folder);
}

[GeneratedComInterface]
[Guid("86627eb4-42a7-41e4-a4d9-ac33a72f2d52")]
internal partial interface IRegisteredTaskCollection
{
    // IDispatch slots. Never called, never removed: they are what keeps everything
    // that follows aligned on the right function.
    void GetTypeInfoCount_Unused();

    void GetTypeInfo_Unused();

    void GetIDsOfNames_Unused();

    void Invoke_Unused();

    [PreserveSig]
    int get_Count(out int count);

    [PreserveSig]
    int get_Item(Wmi.Variant index, out IRegisteredTask task);
}

[GeneratedComInterface]
[Guid("9c86f320-dee3-4dd1-b972-a303f26b061e")]
internal partial interface IRegisteredTask
{
    // IDispatch slots. Never called, never removed: they are what keeps everything
    // that follows aligned on the right function.
    void GetTypeInfoCount_Unused();

    void GetTypeInfo_Unused();

    void GetIDsOfNames_Unused();

    void Invoke_Unused();

    [PreserveSig]
    int get_Name([MarshalAs(UnmanagedType.BStr)] out string name);

    [PreserveSig]
    int get_Path([MarshalAs(UnmanagedType.BStr)] out string path);

    [PreserveSig]
    int get_State(out int state);

    [PreserveSig]
    int get_Enabled(out short enabled);

    void put_Enabled_Unused();

    void Run_Unused();

    void RunEx_Unused();

    void GetInstances_Unused();

    void get_LastRunTime_Unused();

    void get_LastTaskResult_Unused();

    void get_NumberOfMissedRuns_Unused();

    void get_NextRunTime_Unused();

    void get_Definition_Unused();

    /// <summary>
    /// The full definition as XML.
    ///
    /// Preferred over <c>get_Definition</c> and its chain of interfaces — actions,
    /// triggers, principal, each with its own virtual table to declare correctly.
    /// The XML gives the same information in a single read, hence a single
    /// opportunity to get a slot wrong instead of ten.
    /// </summary>
    [PreserveSig]
    int get_Xml([MarshalAs(UnmanagedType.BStr)] out string xml);
}
