using System.Text.RegularExpressions;
using Rempart.Core.Rules;

namespace Rempart.Tests.Unit;

/// <summary>
/// One list of accepted extensions, confronted to the two places that could quietly
/// hold a second one: the sources that discover rule files, and the build glob that
/// embeds them.
///
/// <para>
/// A directory holding <c>a.yaml</c> next to <c>b.yml</c> used to load the first and
/// drop the second without a word. Enumerating the sites by hand is exactly how that
/// happened, so these guards read the tree rather than a list written from memory.
/// </para>
/// </summary>
public sealed class RuleFileTests
{
    [Theory]
    [InlineData("regles.yaml")]
    [InlineData("regles.yml")]
    [InlineData("REGLES.YAML")]
    public void Both_spellings_designate_rules(string name) => Assert.True(RuleFile.Matches(name));

    [Theory]
    [InlineData("loldrivers.json")]
    [InlineData("notes.yaml.bak")]
    [InlineData("regles.yamlx")]
    public void Anything_else_does_not(string name) => Assert.False(RuleFile.Matches(name));

    [Fact]
    public void No_other_source_of_the_core_spells_a_yaml_extension_out()
    {
        // The point of RuleFile. A new discovery site writing ".yaml" on its own would
        // recognise half the rule files and drop the rest in silence — the defect this
        // class was extracted to end.
        var offenders = Directory
            .EnumerateFiles(
                RepositoryFiles.Resolve("src/Rempart.Core"), "*.cs", SearchOption.AllDirectories)
            .Where(file => Path.GetFileName(file) != "RuleFile.cs")
            .Where(file => Regex.IsMatch(File.ReadAllText(file), "\"\\*?\\.ya?ml\""))
            .Select(file => Path.GetFileName(file))
            .ToList();

        Assert.True(offenders.Count == 0,
            $"extension YAML réécrite hors de RuleFile : {string.Join(", ", offenders)}");
    }

    [Fact]
    public void Every_rule_file_of_the_working_tree_reaches_the_binary()
    {
        // The build glob is a second list, in a file no other test opens. A rule saved
        // as .yml would never be embedded, and the shipped catalog would run one check
        // short while claiming to be complete.
        var embedded = typeof(RuleCatalog).Assembly.GetManifestResourceNames();

        var dropped = Directory
            .EnumerateFiles(RepositoryFiles.Resolve("rules"), "*", SearchOption.AllDirectories)
            .Where(RuleFile.Matches)
            .Select(file => Path.GetFileName(file))
            .Where(name => !embedded.Any(r => r.EndsWith($".{name}", StringComparison.Ordinal)))
            .ToList();

        Assert.True(dropped.Count == 0,
            $"règles présentes dans rules/ mais absentes du binaire : {string.Join(", ", dropped)}");
    }
}
