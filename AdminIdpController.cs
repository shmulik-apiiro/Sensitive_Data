#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AccountService.Controllers.Arguments;
using AccountService.Controllers.Responses;
using AccountService.Model;
using AccountService.Services;
using AccountService.Services.Authorization;
using AccountService.Services.Okta;
using AccountService.Utils;
using Infrastructure.Dotnet.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AccountService.Controllers;

[Route("api/admin/idps")]
public class AdminIdpController : BaseController
{
    private readonly IAuditLogService _auditLogService;
    private readonly IEnvironmentService _environmentService;
    private readonly IIdpService _idpService;
    private readonly IUserService _userService;
    private readonly IUserEnvironmentService _userEnvironmentService;
    private readonly IGatewayMappingService _gatewayMappingService;
    private readonly IOktaService _oktaService;

    public AdminIdpController(
        PostgresContext dbContext,
        IAuditLogService auditLogService,
        IEnvironmentService environmentService,
        IIdpService idpService,
        IUserService userService,
        IUserEnvironmentService userEnvironmentService,
        IAuthenticatedUserProvider authenticatedUserProvider,
        IGatewayMappingService gatewayMappingService,
        IOktaService oktaService
    ) : base(
        dbContext,
        authenticatedUserProvider
    )
    {
        _auditLogService = auditLogService;
        _environmentService = environmentService;
        _idpService = idpService;
        _userService = userService;
        _userEnvironmentService = userEnvironmentService;
        _gatewayMappingService = gatewayMappingService;
        _oktaService = oktaService;
    }

    [HttpGet]
    [AllowedRoles(SystemRole.SuperAdmin, SystemRole.PartnerAdmin)]
    public async Task<IActionResult> GetIdpsAsync(string query = null, int page = 1)
    {
        var searchResults = await _idpService.SearchIdpsAsync(
            new SearchParams(
                query,
                null,
                null,
                page,
                DefaultPageSize
            )
        );

        var idps = searchResults.Results.Select(_ => new IdpResponse(_))
            .ToList();

        return Ok(
            new PagedResult<IdpResponse>(
                searchResults.CurrentPage,
                searchResults.PageSize,
                searchResults.RowCount,
                idps
            )
        );
    }

    [HttpGet("{idpId:guid}")]
    [AllowedRoles(SystemRole.SuperAdmin, SystemRole.PartnerAdmin)]
    public async Task<IActionResult> GetIdpByIdAsync(Guid idpId)
    {
        var idp = await _idpService.GetIdpAsync(idpId);
        if (idp == null)
        {
            return NotFound();
        }

        return Ok(new IdpResponse(idp));
    }

    [HttpGet("{idpId:guid}/metadata")]
    [AllowedRoles(SystemRole.SuperAdmin, SystemRole.PartnerAdmin)]
    public async Task<IActionResult> GetIdpMetadataAsync(Guid idpId)
    {
        var idp = await _idpService.GetIdpAsync(idpId);

        if (idp == null)
        {
            return NotFound();
        }

        if (idp.Type.IsOauth())
        {
            return BadRequest("Can only get metadata for SAML idps");
        }

        var metadata = await _idpService.GetIdpMetadataAsync(idp);

        return File(
            metadata.ToBytes(),
            "text/xml",
            "metadata.xml"
        );
    }

    [HttpPost]
    public async Task<ActionResult<IdpResponse>> CreateIdpAsync([FromBody] IdpArgs idpArgs)
    {
        if (!idpArgs.ParsePingMetadata())
        {
            return BadRequest("Invalid metadata xml received");
        }

        var result = ValidateIdp(idpArgs);
        if (result.IsNotOk())
        {
            return result;
        }

        var (success, actionResult) = await VerifyUniqueDomains(idpArgs);
        if (!success)
        {
            return actionResult;
        }

        var idp = await DoCreateIdpAsync(idpArgs);
        return Ok(new IdpResponse(idp));
    }

    [Transactional]
    [HttpPut("{idpId:guid}")]
    public async Task<IActionResult> UpdateIdpAsync(Guid idpId, [FromBody] IdpArgs idpArgs)
    {
        if (!idpArgs.ParsePingMetadata())
        {
            return BadRequest("Invalid metadata xml received");
        }

        var result = ValidateIdp(idpArgs, true);
        if (result.IsNotOk())
        {
            return result;
        }

        var idp = await _idpService.GetIdpAsync(
            idpId,
            true,
            false
        );

        if (idp == null)
        {
            return NotFound();
        }

        var (success, actionResult) = await VerifyUniqueDomains(idpArgs, idp);
        if (!success)
        {
            return actionResult;
        }

        var (usersToAdd, usersToRemove) = await GetUsersToModifyAsync(
            idpArgs.Domains,
            idp.Domains.Select(_ => _.Domain)
                .ToList()
        );
        await _idpService.UpdateIdpAsync(
            idpArgs,
            idp,
            usersToAdd,
            usersToRemove,
            await GetAuthenticatedUserAsync()
        );

        return Ok(new IdpResponse(idp));
    }

    [HttpPut("{idpId:guid}/environments/{environmentId}")]
    [AllowedRoles(SystemRole.SuperAdmin, SystemRole.PartnerAdmin)]
    public async Task<IActionResult> AttachEnvironmentToIdpAsync(Guid idpId, string environmentId, AttachEnvironmentToIdpArgs args)
    {
        var environment = await _environmentService.GetEnvironmentAsync(environmentId, includeAttachedIdpsAndDomains: true);
        var idp = await _idpService.GetIdpAsync(
            idpId,
            false
        );

        if (idp == null)
        {
            return NotFound("Idp not found");
        }

        if (environment == null)
        {
            return NotFound("Environment not found");
        }

        if (!environment.Status.IsActiveState())
        {
            return BadRequest("Cannot attach to inactive environments");
        }

        var environmentAlreadyAttached = idp.AttachedEnvironments.Any(_ => _.EnvironmentId == environmentId);
        if (environment.AttachedIdps.Any() && !environmentAlreadyAttached)
        {
            return Conflict("Environment could only be attached to one IDP");
        }

        if (environmentAlreadyAttached)
        {
            await UpdateEnvironmentIdpAttachmentAsync(idp, environment, args);
        }
        else
        {
            await AttachedEnvironmentToIdpAsync(idp, environment, args);
        }

        await DbContext.SaveChangesAsync();

        return Ok();
    }

    [HttpDelete("{idpId:guid}/environments/{environmentId}")]
    public async Task<IActionResult> DetachEnvironmentFromIdpAsync(Guid idpId, string environmentId)
    {
        var idp = await _idpService.GetIdpAsync(
            idpId,
            false
        );

        if (idp == null)
        {
            return NotFound("Idp not found");
        }

        if (idp.AttachedEnvironments.None(_ => _.EnvironmentId == environmentId))
        {
            return Ok();
        }

        var environment = await _environmentService.GetEnvironmentAsync(environmentId);
        idp.RemoveEnvironment(environment);

        environment.AuthenticationType = AuthenticationType.Regular;
        environment.AdminsGroup = null;

        var userEnvironments = await _userEnvironmentService.GetUserEnvironmentsByEnvironmentIdAsync(environmentId);
        var actorUser = await GetAuthenticatedUserAsync();
        foreach (var userEnvironment in userEnvironments)
        {
            await _auditLogService.LogAsync(
                AuditLogAction.RemovedUserFromEnvironment,
                environment,
                actorUser,
                userId: userEnvironment.UserId
            );

            userEnvironment.ChangeStatus(UserEnvironmentStatus.Removed);
        }

        await _auditLogService.LogAsync(
            AuditLogAction.EnvironmentDetachedFromIdp,
            actorUser: await GetAuthenticatedUserAsync(),
            environment: environment,
            idp: idp
        );
        await DbContext.SaveChangesAsync();

        return Ok();
    }

    [HttpDelete("{idpId:guid}")]
    public async Task<IActionResult> DeleteIdpAsync(Guid idpId)
    {
        var idp = await _idpService.GetIdpAsync(
            idpId,
            true,
            false
        );

        if (idp == null)
        {
            return NotFound("Requested IDP wasn't found");
        }

        await _idpService.DeleteIdpAsync(idp, await GetAuthenticatedUserAsync());
        await DbContext.SaveChangesAsync();

        return Ok();
    }

    [HttpGet("{idpId:guid}/idleSessionTimeout")]
    public async Task<IActionResult> GetIdleSessionTimeoutAsync(Guid idpId)
    {
        var idp = await _idpService.GetIdpAsync(idpId, false, false);
        if (idp == null)
        {
            return NotFound("Requested IDP wasn't found");
        }

        var timoutInMinutes = await _gatewayMappingService.GetIdleSessionTimeoutAsync(idp);
        return Ok(new IdpIdleSessionTimeoutResponse(timoutInMinutes));
    }

    [HttpPut("{idpId:guid}/idleSessionTimeout")]
    public async Task<IActionResult> UpdateIdleSessionTimeoutAsync(Guid idpId, [FromBody] IdleSessionTimeoutArgs idleSessionTimeoutArgs)
    {
        if (idleSessionTimeoutArgs.IdleSessionTimeoutInMinutes < 5 && idleSessionTimeoutArgs.IdleSessionTimeoutInMinutes != 0)
        {
            return BadRequest("Idle session timeout must be at least 5 minutes.");
        }

        if (idleSessionTimeoutArgs.IdleSessionTimeoutInMinutes > TimeSpan.FromHours(4).TotalMinutes)
        {
            return BadRequest("Idle session timeout cannot be more than 4 hours.");
        }

        var idp = await _idpService.GetIdpAsync(idpId, false, false);
        if (idp == null)
        {
            return NotFound("Requested IDP wasn't found");
        }

        if (idp.Type.IsSaml())
        {
            return BadRequest("Saml IDPs do not currently support the idle session timeout feature.");
        }

        var success = await _gatewayMappingService.UpdateIdleSessionTimeoutInRedisAsync(idp, idleSessionTimeoutArgs.IdleSessionTimeoutInMinutes);
        if (!success)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, "Writing to redis failed.");
        }

        await _oktaService.SyncIdleSessionTimeoutRuleAsync(idp, idleSessionTimeoutArgs.IdleSessionTimeoutInMinutes);

        return Ok();
    }

    private async Task<(IReadOnlyCollection<ApiiroUser> usersToAdd, IReadOnlyCollection<ApiiroUser> usersToRemove)> GetUsersToModifyAsync(IReadOnlyCollection<string> newDomains, IReadOnlyCollection<string> oldDomains)
    {
        var removedDomains = oldDomains
            .Where(_ => !newDomains.Contains(_));
        var usersToAdd = await newDomains.ToAsyncEnumerable()
            .SelectMany<string, ApiiroUser>(async (domain, _) => await _userService.GetUsersByDomainAsync(domain))
            .ToListAsync();
        var usersToRemove = await removedDomains.ToAsyncEnumerable()
            .SelectMany<string, ApiiroUser>(async (domain, _) => (await _userService.GetUsersByDomainAsync(domain)))
            .ToListAsync();
        return (usersToAdd, usersToRemove);
    }

    private async Task<Idp> DoCreateIdpAsync(IdpArgs idpArgs)
    {
        var users = await idpArgs.Domains.ToAsyncEnumerable()
            .SelectMany<string, ApiiroUser>(async (domain, _) => (await _userService.GetUsersByDomainAsync(domain)))
            .ToListAsync();
        var idp = await _idpService.CreateIdpAsync(
            idpArgs,
            users,
            await GetAuthenticatedUserAsync()
        );
        await DbContext.SaveChangesAsync();
        return idp;
    }

    private async Task<(bool success, ActionResult actionResult)> VerifyUniqueDomains(IdpArgs idpArgs, Idp currentIdp = null)
    {
        var idpDomainConflicts = await SearchIdpDomainsByDomainsAsync(idpArgs.Domains);
        if (idpDomainConflicts.Any(_ => currentIdp == null || _.AttachedIdp?.Id != currentIdp.Id))
        {
            return (false, Conflict($"The following domains are already assigned to another IDP: {string.Join(", ", idpDomainConflicts.Select(_ => _.Domain).Distinct())}"));
        }

        return (true, null);
    }

    private ActionResult ValidateIdp(IdpArgs idpArgs, bool isUpdate = false)
    {
        if (idpArgs.Type.IsOauth())
        {
            if (!isUpdate && string.IsNullOrEmpty(idpArgs.ClientSecret))
            {
                return BadRequest("Client secret is required to create an IDP");
            }

            if (idpArgs.OauthScopes.NullOrNone())
            {
                return BadRequest("OAuth scopes are required");
            }
        }

        return idpArgs.Type switch
        {
            IdpType.Okta or IdpType.OIDC when string.IsNullOrEmpty(idpArgs.Issuer) => BadRequest("Issuer is required for Okta IDPs"),
            IdpType.AAD when string.IsNullOrEmpty(idpArgs.TenantId) => BadRequest("Directory (tenant) ID is required for AAD IDPs"),
            IdpType.OIDC when string.IsNullOrEmpty(idpArgs.Authorization) || string.IsNullOrEmpty(idpArgs.Token) || string.IsNullOrEmpty(idpArgs.Jwks) => BadRequest("Missing required endpoints"),
            IdpType.SAML2 when string.IsNullOrEmpty(idpArgs.Issuer) || (!isUpdate && string.IsNullOrEmpty(idpArgs.SamlCertificate)) => BadRequest("Missing required fields"),
            _ => Ok()
        };
    }

    private async Task<IReadOnlyCollection<IdpDomain>> SearchIdpDomainsByDomainsAsync(IEnumerable<string> domains)
        => (await domains.ToAsyncEnumerable()
                .Select(async (string domain, CancellationToken _) => await _idpService.SearchIdpsByDomainAsync(domain))
                .ToListAsync())
            .Flatten()
            .ToList();

    private async Task UpdateEnvironmentIdpAttachmentAsync(Idp idp, ApiiroEnvironment environment, AttachEnvironmentToIdpArgs args)
    {
        var attachedEnvironmentIdp = idp.AttachedEnvironmentIdps.First(_ => _.EnvironmentId == environment.EnvironmentId);
        attachedEnvironmentIdp.EnvironmentAccessIdpGroup = args.EnvironmentAccessIdpGroup;
        await _auditLogService.LogAsync(
            AuditLogAction.EnvironmentIdpAttachmentUpdated,
            environment,
            await GetAuthenticatedUserAsync(),
            idp
        );
    }

    private async Task AttachedEnvironmentToIdpAsync(Idp idp, ApiiroEnvironment environment, AttachEnvironmentToIdpArgs args)
    {
        environment.AuthenticationType = AuthenticationType.IDP;
        idp.AddEnvironment(environment, args.EnvironmentAccessIdpGroup);
        await _auditLogService.LogAsync(
            AuditLogAction.EnvironmentAttachedToIdp,
            environment,
            await GetAuthenticatedUserAsync(),
            idp
        );
    }
}