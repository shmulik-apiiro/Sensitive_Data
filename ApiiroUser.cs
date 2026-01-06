#nullable disable

using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using AccountService.Model.Attributes;
using AccountService.Services.Authorization;
using Infrastructure.Dotnet.Common;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;

namespace AccountService.Model;

[Index(nameof(Email), IsUnique = true)]
public class ApiiroUser : ISnapshot, IPartnerScoped
{
    private static readonly IReadOnlyList<string> LoggableProperties = new[]
    {
        nameof(UserId),
        nameof(ActivatedInOkta),
        nameof(CreatedAt)
    };

    [Key]
    public Guid UserId { get; set; }

    [Required]
    public string Email { get; set; }

    [NotMapped]
    public string EmailDomain => Email.Split('@')
        .Last();

    [DefaultValue(false)]
    public bool ActivatedInOkta { get; set; }

    public EulaSignature EulaSignature { get; set; }

    public string FirstName { get; set; }

    public string LastName { get; set; }

    public string DisplayName => $"{FirstName} {LastName}";

    public ICollection<UserEnvironment> UserEnvironments { get; set; }

    [SqlDefaultValueUtcNow]
    public DateTime CreatedAt { get; set; }

    [NotMapped]
    public HashSet<SystemRole> Roles { get; set; }

    [NotMapped]
    public HashSet<string> Groups { get; set; }

    [CanBeNull]
    public string IdpGroups { get; set; }

    [CanBeNull]
    public Partner Partner { get; set; }

    [NotMapped]
    [CanBeNull]
    public IReadOnlyCollection<string> UserIdpGroups
    {
        get => IdpGroups?.FromJson<IReadOnlyCollection<string>>();
        set => IdpGroups = value?.ToJson();
    }

    public bool ReceivesLimApiAdminAccess => Roles.Any(_ => _.AuthorizesLimApiAdminAccess());

    public bool HasAccountServiceDashboardAccess => Roles.Any(_ => _ != SystemRole.User);

    public bool IsPartnerAdmin => Roles?.Contains(SystemRole.PartnerAdmin) ?? false;

    public bool WorksAtApiiro => Email.EndsWith("@apiiro.com");

    public IEnumerable<string> SnapshotProperties => LoggableProperties;

    public static ApiiroUser Create(string email, string firstName, string lastName)
        => new()
        {
            UserId = Guid.NewGuid(),
            Email = email.Trim()
                .ToLower(),
            FirstName = firstName,
            LastName = lastName
        };

    public override string ToString()
        => ((ISnapshot)this).GetSnapshot();
}