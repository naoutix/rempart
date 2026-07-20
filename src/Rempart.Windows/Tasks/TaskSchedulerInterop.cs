using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace Rempart.Windows.Tasks;

/// <summary>
/// Interfaces COM du planificateur de tâches, déclarées pour le générateur d'interop.
///
/// Même démarche que pour WMI : <c>GeneratedComInterface</c> produit la transition à
/// la compilation, sans réflexion, donc compatible Native AOT.
///
/// <para>
/// Une différence essentielle avec WMI : ces interfaces dérivent d'<c>IDispatch</c>,
/// pas d'<c>IUnknown</c>. Quatre emplacements supplémentaires les précèdent donc dans
/// la table virtuelle — <c>GetTypeInfoCount</c>, <c>GetTypeInfo</c>,
/// <c>GetIDsOfNames</c>, <c>Invoke</c>. Les omettre appellerait la mauvaise fonction
/// avec les mauvais arguments : un plantage si l'on a de la chance, un résultat faux
/// sinon.
/// </para>
///
/// <para>
/// L'ordre des méthodes est repris de <c>taskschd.h</c> du SDK Windows, pas de
/// mémoire. Un décalage d'un seul emplacement est invisible à la compilation et se
/// paie à l'exécution.
/// </para>
/// </summary>
internal static class TaskSchedulerIds
{
    internal static readonly Guid ClsidTaskScheduler =
        new("0f87369f-a4e5-4cfc-bd3e-73e6154572dd");

    internal static readonly Guid IidTaskService =
        new("2faba4c7-4da9-4013-9697-20cc3fd40f85");

    /// <summary>
    /// Inclut les tâches masquées. Un audit qui ne les verrait pas manquerait
    /// exactement celles qu'on prend soin de cacher.
    /// </summary>
    internal const int EnumHidden = 1;
}

[GeneratedComInterface]
[Guid("2faba4c7-4da9-4013-9697-20cc3fd40f85")]
internal partial interface ITaskService
{
    // Emplacements d'IDispatch. Jamais appeles, jamais retires : ils sont ce qui
    // aligne tout ce qui suit sur la bonne fonction.
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
    /// Quatre VARIANT vides désignent la machine locale et l'utilisateur courant.
    /// Le VARIANT est déclaré comme une structure blittable — l'interop générée ne
    /// sait pas l'exprimer autrement, c'est la même contrainte que pour WMI.
    /// </summary>
    [PreserveSig]
    int Connect(Wmi.Variant server, Wmi.Variant user, Wmi.Variant domain, Wmi.Variant password);
}

[GeneratedComInterface]
[Guid("8cfac062-a080-4c15-9a88-aa7c2af80dfc")]
internal partial interface ITaskFolder
{
    // Emplacements d'IDispatch. Jamais appeles, jamais retires : ils sont ce qui
    // aligne tout ce qui suit sur la bonne fonction.
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
    // Emplacements d'IDispatch. Jamais appeles, jamais retires : ils sont ce qui
    // aligne tout ce qui suit sur la bonne fonction.
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
    // Emplacements d'IDispatch. Jamais appeles, jamais retires : ils sont ce qui
    // aligne tout ce qui suit sur la bonne fonction.
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
    // Emplacements d'IDispatch. Jamais appeles, jamais retires : ils sont ce qui
    // aligne tout ce qui suit sur la bonne fonction.
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
    /// La définition complète en XML.
    ///
    /// Préférée à <c>get_Definition</c> et à sa chaîne d'interfaces — actions,
    /// déclencheurs, principal, chacune avec sa propre table virtuelle à déclarer
    /// correctement. Le XML donne la même information en une seule lecture, donc en
    /// une seule occasion de se tromper d'emplacement au lieu de dix.
    /// </summary>
    [PreserveSig]
    int get_Xml([MarshalAs(UnmanagedType.BStr)] out string xml);
}
