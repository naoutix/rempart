using System.Reflection;

namespace Rempart.Tests.Unit;

/// <summary>
/// Reading the string constants a static table declares, for the guards built on top of one.
///
/// <para>
/// Shared rather than copied, for the reason <see cref="JsonHoles"/> gives about itself: two
/// guards derive their coverage from <see cref="Rempart.Core.Updates.DatasetKind"/>, and two
/// copies of the read are two chances for one of them to go blind on its own. They already
/// had: the copy in <c>DatasetHoleTests</c> was widened to see both forms and the one in
/// <c>UpdatePlannerTests</c> was not, so the same table was fully read by one guard and
/// half-read by the other for as long as nobody compared them (issue #163).
/// </para>
/// </summary>
internal static class StringTables
{
    /// <summary>
    /// Every string <paramref name="table"/> declares, in both forms a public static string
    /// field can take.
    ///
    /// <para>
    /// <c>const</c> is what the tables of this repository write today and the only form the
    /// first version of this read saw. <c>static readonly</c> is just as ordinary, and is the
    /// only form left the day a value stops being a compile-time literal — computed from a
    /// prefix, read off another constant, anything. Declared that way, a dataset kind would
    /// have arrived with no reader, no exclusion and no red, and a policy fact name with no
    /// surface establishing it: the guard would have kept passing by sweeping one fewer thing,
    /// which is the one failure a guard must not have.
    /// </para>
    ///
    /// <para>
    /// The honest limit, stated rather than left to be discovered: a value that never becomes
    /// a field of the table at all — a string written straight into a <c>switch</c> arm —
    /// routes just as well and is invisible here.
    /// </para>
    /// </summary>
    public static IReadOnlyList<string> Declared(Type table) =>
        [.. table
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.FieldType == typeof(string)
                && (field.IsLiteral || field.IsInitOnly))
            // GetRawConstantValue is the only one that answers for a const, GetValue the only
            // one that answers for a static readonly.
            .Select(field => field.IsLiteral
                ? field.GetRawConstantValue()
                : field.GetValue(null))
            .OfType<string>()];
}
