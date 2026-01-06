using JetBrains.Annotations;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;

namespace Lim.Common.DotNET;

[MongoCollection("riskLifecycle", includeInBackup: true)]
[StorageSerialization]
public class RiskLifecycleData : BaseDocument, IScopedEntity
{
    private DateTime? _updatedAt;

    [BsonConstructor]
    public RiskLifecycleData()
    {
    }

    public DateTime? UpdatedAt
    {
        get =>
            _updatedAt = DetermineLatestUpdate(
                _updatedAt,
                ResolvedAt,
                DiscoveredAt
            );
        set
            => _updatedAt = value;
    }

    [BsonId]
    public required string TriggerKey { get; set; }

    public RiskLifecycleStatus Status { get; set; }

    public RiskLifecycleClosedReason ClosedReason { get; set; }

    public DateTime DiscoveredAt { get; set; }

    public DateTime? ResolvedAt { get; set; }

    public DateTime? DueDate { get; set; }

    [MongoIndex]
    public required string ProfileKey { get; set; }

    public required string ProfileType { get; set; }

    public string? RuleKey { get; set; }

    public string? EntityTriggerKey { get; set; }

    public string? ElementKey { get; set; }

    public RiskTriggerElementType ElementType { get; set; }

    public required DataModelReference? PrimaryDataModelReference { get; set; }

    public RiskLevel RuleRiskLevel { get; set; }

    public RiskLevel? RiskLevel { get; set; }
    public int RiskScore { get; set; }
    public RiskStatus? RiskStatus { get; set; }

    public HashSet<string> AssetCollectionKeys { get; set; } = [];

    public RiskCategory RiskCategory { get; set; }

    public string? RiskName { get; set; }

    public string? ModuleName { get; set; }

    public string? RuleName { get; set; }

    public string? ServerUrl { get; set; }

    public ISet<string> Sources { get; set; } = new HashSet<string>();

    public List<RiskTriggerInsight> Insights { get; set; } = [];

    [BsonIgnoreIfNull]
    public string? CodeOwnerIdentityKey { get; set; }

    [BsonIgnoreIfNull]
    public string? DependencyName { get; set; }

    [BsonIgnoreIfNull]
    public double? CVSSScore { get; set; }

    [BsonIgnoreIfNull]
    [BsonRepresentation(BsonType.Int32)]
    public DependencyDeclarationType? DeclarationType { get; set; }

    public HashSet<string> VulnerabilityNames { get; set; } = [];

    public List<ComplianceFrameworkReference?>? ComplianceFrameworkReferences { get; set; } = [];

    public HashSet<OSSRiskTriggerSummary.VulnerabilityDescriptor> Vulnerabilities { get; set; } = [];

    public HashSet<ProcessTag> ProcessTags { get; set; } = [];

    [BsonIgnoreIfNull]
    [BsonRepresentation(BsonType.Int32)]
    public DependencyType? PackageManager { get; set; }

    [BsonIgnoreIfNull]
    [BsonRepresentation(BsonType.Int32)]
    public SecretValidationResult? Validity { get; set; }

    [BsonIgnoreIfNull]
    public SecretExposure? Exposure { get; set; }

    [BsonIgnoreIfNull]
    public SecretType? SecretType { get; set; }

    [BsonIgnoreIfNull]
    public ExternalPlatform? SecretPlatform { get; set; }

    [BsonIgnoreIfNull]
    public FileClassification? FileClassification { get; set; }

    public Language? Language { get; set; }

    [BsonIgnoreIfNull]
    public string? HttpMethod { get; set; }

    [BsonIgnoreIfNull]
    public string? HttpRoute { get; set; }

    [BsonIgnoreIfNull]
    [CanBeNull]
    public string? FindingName { get; set; }

    [BsonIgnoreIfNull]
    public string? FindingType { get; set; }

    [BsonIgnoreIfNull]
    public string? FindingSeverity { get; set; }

    [BsonIgnoreIfNull]
    public string? FindingLink { get; set; }

    [BsonIgnoreIfNull]
    public string? FindingStatus { get; set; }

    [BsonIgnoreIfNull]
    public string? FindingLocationUrl { get; set; }

    public CodeReference? CodeReference { get; set; }

    [BsonIgnoreIfNull]
    public int? ChunkHint { get; set; }

    public bool HasPermissionInScope(UserScope userScope, AccessType accessType)
        => ProfileType switch
        {
            nameof(RepositoryProfile) => userScope.ContainsRepositoryKey(ProfileKey),
            nameof(ProjectProfile) => userScope.ContainsProjectKey(ProfileKey),
            ProcessedFinding.UnmatchedProfile => userScope.ContainsAnyAssetCollectionKey(AssetCollectionKeys),
            _ => false
        };

    private static DateTime? DetermineLatestUpdate(DateTime? updatedAt, DateTime? resolvedAt, DateTime discoveredAt)
    {
        if (!updatedAt.HasValue)
        {
            return resolvedAt ?? discoveredAt;
        }

        if (resolvedAt.HasValue)
        {
            return resolvedAt > updatedAt
                ? resolvedAt
                : updatedAt;
        }

        return updatedAt;
    }

    [IndexProvider]
    public static IEnumerable<CreateIndexModel<RiskLifecycleData>> CreateCustomIndexes()
    {
        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Ascending(nameof(DiscoveredAt))
                .Ascending(nameof(RuleRiskLevel))
                .Ascending(nameof(AssetCollectionKeys))
        );

        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Ascending(nameof(ResolvedAt))
                .Ascending(nameof(Status))
                .Ascending(nameof(RuleRiskLevel))
                .Ascending(nameof(AssetCollectionKeys))
        );

        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Descending(nameof(DiscoveredAt))
                .Ascending(nameof(RiskCategory))
                .Ascending(nameof(RiskLevel))
        );

        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Descending(nameof(ResolvedAt))
                .Ascending(nameof(RiskCategory))
                .Ascending(nameof(RiskLevel))
                .Ascending(nameof(Status))
        );

        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Ascending(nameof(DiscoveredAt))
                .Descending(nameof(ResolvedAt))
                .Ascending(nameof(RuleRiskLevel))
        );

        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Ascending(nameof(ProfileKey))
                .Ascending(nameof(ChunkHint))
        );

        yield return new CreateIndexModel<RiskLifecycleData>(
            new IndexKeysDefinitionBuilder<RiskLifecycleData>()
                .Ascending(nameof(Status))
                .Ascending(nameof(ProfileKey))
        );
    }

    public int UniquenessCode()
    {
        var hashCode = new CompositeHashCode();
        hashCode.Add(TriggerKey);
        hashCode.Add(Status);
        hashCode.Add(DiscoveredAt);
        hashCode.Add(ResolvedAt);
        hashCode.Add(DueDate);
        hashCode.Add(ProfileKey);
        hashCode.Add(ProfileType);
        hashCode.Add(RuleRiskLevel);
        hashCode.Add(RiskScore);
        hashCode.Add(RiskLevel);
        hashCode.Add(AssetCollectionKeys);
        hashCode.Add(RiskCategory);
        hashCode.Add(RiskName);
        hashCode.Add(ModuleName);
        hashCode.Add(RuleName);
        hashCode.Add(ServerUrl);
        hashCode.Add(Insights);
        hashCode.Add(CodeOwnerIdentityKey);
        hashCode.Add(VulnerabilityNames);
        hashCode.Add(Vulnerabilities);
        hashCode.Add(ProcessTags);
        hashCode.Add(DeclarationType);
        hashCode.Add(CVSSScore);
        hashCode.Add(PackageManager);
        hashCode.Add(DependencyName);
        hashCode.Add(Sources);
        hashCode.Add(RiskStatus);
        hashCode.Add(Validity);
        hashCode.Add(CodeReference);
        hashCode.Add(HttpMethod);
        hashCode.Add(Language);
        hashCode.Add(ClosedReason);
        hashCode.Add(PrimaryDataModelReference);
        return hashCode.ToHashCode();
    }
}
