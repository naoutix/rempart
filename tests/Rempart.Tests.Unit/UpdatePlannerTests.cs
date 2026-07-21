using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Rempart.Core.Json;
using Rempart.Core.Rules;
using Rempart.Core.Updates;

namespace Rempart.Tests.Unit;

public class UpdatePlannerTests
{
    private const string BaseRule = """
        - id: WIN-TEST-001
          title: Un contrôle
          severity: high
          domain: test
          check:
            type: registry
            path: HKLM\Software\Test
            value: Flag
            operator: equals
            expect: "1"
            windowsDefault: "0"
          rationale: Pour le test.
          references: []
        """;

    private static IReadOnlyList<Rule> Current() => RuleLoader.Load(BaseRule);

    /// <summary>
    /// Assemble un manifeste signé et le lecteur de jeux de données qui va avec, pour
    /// que la préparation voie exactement ce qu'elle verrait sur disque.
    /// </summary>
    private static (string Manifest, Func<string, byte[]?> Read, ManifestVerifier Verifier)
        Publish(TestPublisher publisher, string datasetName, string yaml)
    {
        var bytes = Encoding.UTF8.GetBytes(yaml);
        var entry = new ManifestEntry(
            datasetName, "2.0.0",
            Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes.Length);

        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new ManifestPayload(1, "2026-08-01T00:00:00Z", [entry]),
            RempartJsonContext.Default.ManifestPayload);

        var manifest = RempartJson.Serialise(new SignedManifest(
            Convert.ToBase64String(payload),
            [new ManifestSignature(publisher.KeyId, publisher.Sign(payload))]));

        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [publisher.KeyId] = publisher.PublicKey });

        byte[]? Read(string name) => name == datasetName ? bytes : null;

        return (manifest, Read, verifier);
    }

    [Fact]
    public void An_added_rule_shows_up_as_added()
    {
        using var publisher = new TestPublisher();
        var yaml = BaseRule + """

            - id: WIN-TEST-002
              title: Un second contrôle
              severity: medium
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: Autre
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;

        var (manifest, read, verifier) = Publish(publisher, "regles.yaml", yaml);

        var preview = UpdatePlanner.Prepare(manifest, verifier, read, Current());
        var diff = Assert.Single(preview.Datasets).Diff!;

        Assert.True(preview.ReadyToApply);
        Assert.Equal(["WIN-TEST-002"], diff.Added);
        Assert.Empty(diff.Modified);
        Assert.Equal(1, diff.Unchanged);
    }

    /// <summary>
    /// Changer un seuil modifie le contrôle ; reformuler la justification, non. Le
    /// différentiel se juge sur l'empreinte par règle, la même que celle du rapport.
    /// </summary>
    [Fact]
    public void A_changed_threshold_is_a_modification_but_a_reworded_rationale_is_not()
    {
        using var publisher = new TestPublisher();

        var changedThreshold = BaseRule.Replace("expect: \"1\"", "expect: \"2\"");
        var (m1, r1, v1) = Publish(publisher, "regles.yaml", changedThreshold);
        var modified = Assert.Single(UpdatePlanner.Prepare(m1, v1, r1, Current()).Datasets).Diff!;

        Assert.Equal(["WIN-TEST-001"], modified.Modified.Select(c => c.Id));

        var rewordedOnly = BaseRule.Replace("Pour le test.", "Une autre formulation.");
        var (m2, r2, v2) = Publish(publisher, "regles.yaml", rewordedOnly);
        var unchanged = Assert.Single(UpdatePlanner.Prepare(m2, v2, r2, Current()).Datasets).Diff!;

        Assert.True(unchanged.ChangesNothing);
    }

    /// <summary>
    /// Le socle est un plancher (D12) : un contrôle embarqué absent de la mise à jour
    /// n'est pas « retiré », il reste. Le différentiel ne l'annonce donc pas comme un
    /// changement.
    /// </summary>
    [Fact]
    public void A_rule_the_update_omits_is_not_reported_as_removed()
    {
        using var publisher = new TestPublisher();

        // La mise à jour ne contient qu'une règle nouvelle, et tait la règle embarquée.
        var onlyNew = """
            - id: WIN-TEST-999
              title: Nouveau
              severity: low
              domain: test
              check:
                type: registry
                path: HKLM\Software\Test
                value: Neuf
                operator: equals
                expect: "1"
                windowsDefault: "0"
              rationale: Pour le test.
              references: []
            """;

        var (manifest, read, verifier) = Publish(publisher, "regles.yaml", onlyNew);
        var diff = Assert.Single(UpdatePlanner.Prepare(manifest, verifier, read, Current()).Datasets).Diff!;

        Assert.Equal(["WIN-TEST-999"], diff.Added);
        Assert.Empty(diff.Modified);
        // WIN-TEST-001 embarquée n'apparaît nulle part : ni retirée, ni comptée.
    }

    /// <summary>
    /// Un manifeste authentique mais dont un fichier ne correspond pas à son empreinte :
    /// jeu de données non vérifié, mise à jour non applicable. Distinct d'une signature
    /// invalide.
    /// </summary>
    [Fact]
    public void A_dataset_that_does_not_match_its_hash_blocks_the_update()
    {
        using var publisher = new TestPublisher();
        var (manifest, _, verifier) = Publish(publisher, "regles.yaml", BaseRule);

        // Le lecteur rend un contenu différent de celui qu'a signé le manifeste.
        byte[]? tampered(string name) => Encoding.UTF8.GetBytes("- id: FAUX");

        var preview = UpdatePlanner.Prepare(manifest, verifier, tampered, Current());
        var dataset = Assert.Single(preview.Datasets);

        Assert.False(dataset.Verified);
        Assert.False(preview.ReadyToApply);
        Assert.Contains("ne correspond", dataset.Problem);
    }

    [Fact]
    public void A_missing_dataset_file_blocks_the_update()
    {
        using var publisher = new TestPublisher();
        var (manifest, _, verifier) = Publish(publisher, "regles.yaml", BaseRule);

        var preview = UpdatePlanner.Prepare(manifest, verifier, _ => null, Current());

        Assert.False(Assert.Single(preview.Datasets).Verified);
        Assert.False(preview.ReadyToApply);
    }

    /// <summary>
    /// Un manifeste signé par une clé inconnue n'est même pas examiné pour ses données :
    /// leur intégrité ne veut rien dire si ce qui les décrit n'est pas authentique.
    /// </summary>
    [Fact]
    public void An_untrusted_manifest_is_not_inspected_further()
    {
        using var publisher = new TestPublisher();
        using var stranger = new TestPublisher();
        var (manifest, read, _) = Publish(publisher, "regles.yaml", BaseRule);

        // Vérificateur qui ne connaît que l'inconnu, pas l'éditeur du manifeste.
        var verifier = new ManifestVerifier(
            new Dictionary<string, string> { [stranger.KeyId] = stranger.PublicKey });

        var preview = UpdatePlanner.Prepare(manifest, verifier, read, Current());

        Assert.False(preview.Trusted);
        Assert.Equal(ManifestStatus.UnknownKey, preview.Status);
        Assert.Empty(preview.Datasets);
    }

    /// <summary>
    /// Fichier authentique et intègre, mais que cette version ne sait pas lire : dit
    /// illisible, pas corrompu. Ce n'est pas une attaque.
    /// </summary>
    [Fact]
    public void A_verified_but_unparseable_dataset_is_reported_as_unreadable()
    {
        using var publisher = new TestPublisher();
        var (manifest, read, verifier) = Publish(
            publisher, "regles.yaml", "ceci n'est pas une règle YAML valide: [");

        var dataset = Assert.Single(
            UpdatePlanner.Prepare(manifest, verifier, read, Current()).Datasets);

        Assert.False(dataset.Verified);
        Assert.Contains("illisible", dataset.Problem);
    }
}
