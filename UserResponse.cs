#nullable disable

using System;
using System.Collections.Generic;
using AccountService.Model;
using AccountService.Services.Authorization;

namespace AccountService.Controllers.Responses;

public class UserResponse
{
    public UserResponse(ApiiroUser user)
    {
        Id = user.UserId;
        Email = user.Email;
        EulaVersion = user.EulaSignature?.EulaVersion;
        EulaDate = user.EulaSignature?.SignatureDate;
        DisplayName = user.DisplayName;
        FirstName = user.FirstName;
        LastName = user.LastName;
        CreatedAt = user.CreatedAt;
        ActivatedInOkta = user.ActivatedInOkta;
        Roles = user.Roles;
        UserIdpGroups = user.UserIdpGroups;
        Partner = user.Partner != null ? new PartnerResponse(user.Partner) : null;
    }

    public Guid Id { get; set; }

    public string EulaVersion { get; set; }

    public DateTime? EulaDate { get; set; }

    public string Email { get; set; }

    public string DisplayName { get; set; }

    public string FirstName { get; set; }

    public string LastName { get; set; }

    public DateTime CreatedAt { get; set; }

    public bool ActivatedInOkta { get; set; }

    public HashSet<SystemRole> Roles { get; set; }

    public IReadOnlyCollection<string> UserIdpGroups { get; set; }

    public PartnerResponse Partner { get; set; }
}