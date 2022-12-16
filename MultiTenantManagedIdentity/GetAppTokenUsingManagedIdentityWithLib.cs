using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Attributes;
using Microsoft.Azure.WebJobs.Extensions.OpenApi.Core.Enums;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.OpenApi.Models;
using Smartersoft.Identity.Client;
using Smartersoft.Identity.Client.Assertion;

namespace MultiTenantManagedIdentity
{
    public class GetAppTokenUsingManagedIdentityWithLib
    {
        private readonly ILogger<GetAppTokenUsingManagedIdentityWithLib> _logger;

        public GetAppTokenUsingManagedIdentityWithLib(ILogger<GetAppTokenUsingManagedIdentityWithLib> log)
        {
            _logger = log;
        }

        [FunctionName("GetAppTokenUsingManagedIdentityWithLib")]
        [OpenApiOperation(operationId: "GetAppTokenUsingManagedIdentityWithLib", tags: new[] { "App" }, Description = "Get app token using a token from managed identity as client credential, with library")]
        [OpenApiSecurity("function_key", SecuritySchemeType.ApiKey, Name = "code", In = OpenApiSecurityLocationType.Query)]
        [OpenApiParameter(name: "clientId", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The client ID for the actual app, where you configured the federated credential")]
        [OpenApiParameter(name: "fedScope", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The scope to get the token that will be used as federeted credential")]
        [OpenApiParameter(name: "scope", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The scope you want to request the actual token for")]
        [OpenApiParameter(name: "tenantId", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The Tenant ID of the tenant where your app is granted access, can be different then current tenant")]
        [OpenApiResponseWithBody(statusCode: HttpStatusCode.OK, contentType: "application/json", bodyType: typeof(AuthenticationResult), Description = "The OK response")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            CancellationToken cancellationToken = default)
        {
            string clientId = req.Query["clientId"];
            string tenantId = req.Query["tenantId"];

            string federatedScope = req.Query["fedScope"];
            string scope = req.Query["scope"];

            var app = ConfidentialClientApplicationBuilder
                .Create(clientId)
                .WithAuthority(AzureCloudInstance.AzurePublic, tenantId)
                // This is the magic
                // See https://github.com/Smartersoft/identity-client-assertion/blob/62e6e7c0fc00487a97f62c02aa1865f4ad9f55b4/src/Smartersoft.Identity.Client.Assertion/ConfidentialClientApplicationBuilderExtensions.cs#L147-L163
                .WithManagedIdentity(federatedScope)
                .Build();


            var result = await app
                .AcquireTokenForClient(new[] {scope})
                .ExecuteAsync(cancellationToken);

            return new OkObjectResult(result);
        }
    }
}

