using System;
using System.IO;
using System.Linq.Expressions;
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
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;

namespace MultiTenantManagedIdentity
{
    public class GetManagedIdentityToken
    {
        private readonly ILogger<GetManagedIdentityToken> _logger;

        public GetManagedIdentityToken(ILogger<GetManagedIdentityToken> log)
        {
            _logger = log;
        }

        [FunctionName("GetManagedIdentityToken")]
        [OpenApiOperation(operationId: "GetManagedIdentityToken", tags: new[] { "Token" })]
        [OpenApiSecurity("function_key", SecuritySchemeType.ApiKey, Name = "code", In = OpenApiSecurityLocationType.Query)]
        [OpenApiParameter(name: "scope", In = ParameterLocation.Query, Required = true, Type = typeof(string), Description = "The **scope** you want to request a token for.")]
        
        [OpenApiResponseWithBody(HttpStatusCode.OK, "application/json", typeof (AccessToken), Description = "An access token for an app in your local tenant")]
        public async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            CancellationToken cancellationToken = default)
        {

            string scope = req.Query["scope"];
            _logger.LogInformation("Requesting token for {scope} using managed identity", scope);
            try
            {
                var credential = new ManagedIdentityCredential();

                var result = await credential.GetTokenAsync(new Azure.Core.TokenRequestContext(new[] { scope }), cancellationToken);

                return new OkObjectResult(result);
            } catch (Exception e)
            {
                _logger.LogError(e, "Error getting token");
                return new StatusCodeResult(500);
            }
            
        }
    }
}

