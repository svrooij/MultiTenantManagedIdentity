using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
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
    public class GetAppTokenUsingManagedIdentity
    {
        private readonly ILogger<GetAppTokenUsingManagedIdentity> _logger;

        public GetAppTokenUsingManagedIdentity(ILogger<GetAppTokenUsingManagedIdentity> log)
        {
            _logger = log;
        }

        [FunctionName("GetAppTokenUsingManagedIdentity")]
        [OpenApiOperation(operationId: "GetAppTokenUsingManagedIdentity", tags: new[] { "App" }, Description = "Get app token using a token from managed identity as client credential")]
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
                .WithClientAssertion(async (AssertionRequestOptions options) =>
                {
                    var credential = new ManagedIdentityCredential();
                    var tokenResult = await credential.GetTokenAsync(new TokenRequestContext(new[] { federatedScope }), options.CancellationToken);
                    return tokenResult.Token;
                })
                .Build();

            // At this point the confidential app is configured with:
            // 1. Client ID
            // 2. Authority (combination of correct cloud and Tenant ID)
            // 3. A callback for dynamically generating a client assertion
            // Remember this is a callback and will not be used unless the assertion is required (for instance to get a token)
            // Normally you would generate an assertion from a certificate in the local computer/current user store
            // but Microsoft has federated credentials in preview and it seems possible to use a managed identity as a federated credential

            // more details in https://svrooij.io/2022/06/21/managed-identity-multi-tenant-app/

            // If you use the app configured above it will execute these steps when you request a token

            // 1. use the callback to get a client assertion,
            //   which in turn uses the ManagedIdentity to request a token for the federation scope you specific.
            // 2. does a Get token request, appending the federated token as a client assertion.
            //
            // See https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential

            var result = await app
                .AcquireTokenForClient(new[] {scope})
                .ExecuteAsync(cancellationToken);

            return new OkObjectResult(result);
        }
    }
}

