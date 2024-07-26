# How to get OIDC working in DotNet 8

I could not get the official examples or documentation for this to completely work, so this information is cobbled together from various tutorials and other people's example projects on GitHub.

This does not add any actual security after the login - either implement that in code or use you OIDC provider to restrict access

This guidance is missing functionality for logging _out_, because I don't need that for my typical use case. I may add this in the future, but the instructions on this page will likely be out of date again by the time I need that functionality myself.

# Add required nuget packages
```ps
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Authentication.OpenIdConnect
```

This example pulls in OIDC details (such as client id, client secret, etc) from either Environment Variables or DotNet User-Secrets (for development). If you are not using either of these, then you don't need these lines:
```ps
dotnet add package Microsoft.Extensions.Configuration.EnvironmentVariables
dotnet add package Microsoft.Extensions.Configuration.UserSecrets
```
# Code additions
## /Components/app.razor

Change this:
```html
﻿...
<body>
    <Routes />
    <script src="_framework/blazor.web.js"></script>
</body>

...
```

To this:

```html
...

<body>
    <AuthorizeView>
        <Authorized>
            <Routes />
            <script src="_framework/blazor.web.js"></script>
        </Authorized>
        <NotAuthorized>
            <RedirectToLogin />
        </NotAuthorized>
    </AuthorizeView>
</body>

...
```
## /Components/RedirectToLogin.razor
New file:
```cs
@inject NavigationManager NavigationManager

@code {
    protected override void OnInitialized()
    {
        NavigationManager.NavigateTo($"authentication/login?returnUrl={Uri.EscapeDataString(NavigationManager.Uri)}", forceLoad: true);
    }
}
```

## /Program.cs
Add some library references at the top
```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
```

Add this above "builder.Services.AddRazorComponents()"
```cs
// Add blazor authentication
const string MS_OIDC_SCHEME = "MicrosoftOidc";
builder.Services.AddAuthentication(MS_OIDC_SCHEME)
    .AddOpenIdConnect(MS_OIDC_SCHEME, oidcOptions =>
    {
        // Pull in configuration, so we can get the OIDC info
        IConfiguration Configuration = new ConfigurationBuilder()
                    .AddEnvironmentVariables()
                    .AddUserSecrets<Program>()
                    .Build();

        oidcOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;        
        oidcOptions.Scope.Add("openid");
        oidcOptions.Scope.Add("profile");
        oidcOptions.Scope.Add(OpenIdConnectScope.OpenIdProfile);
        oidcOptions.GetClaimsFromUserInfoEndpoint = true;
        oidcOptions.Authority = Configuration["OIDC:Authority"];
        oidcOptions.ClientId = Configuration["OIDC:ClientId"];
        oidcOptions.ClientSecret = Configuration["OIDC:ClientSecret"];
        oidcOptions.SaveTokens = true;
        oidcOptions.ResponseType = OpenIdConnectResponseType.Code;
        oidcOptions.TokenValidationParameters = new TokenValidationParameters
        {
            NameClaimType = "name",
            RoleClaimType = "groups",
            ValidateIssuer = true
        };
        oidcOptions.Events = new OpenIdConnectEvents
        {
            OnAccessDenied = context =>
            {
                context.HandleResponse();
                context.Response.Redirect("/");
                return Task.CompletedTask;
            }
        };
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.AddAuthorization();
builder.Services.AddCascadingAuthenticationState();
```
Since I'm using environment variables and user-secrets for OIDC information during development, the above code pulls in the required OIDC information from those. 
You may want to use a different solution depending on your situation.
**Do not hard-code your OIDC details into your source code,** find a more secure way.

Then after `app.UseHttpsRedirection();` add:
```cs
app.UseAuthentication();
app.UseAuthorization();
```

Then just before `app.Run();` add:
```cs
app.MapGroup("/authentication").MapLoginAndLogout();
```

## /LoginLogoutEndpointRouteBuilderExtensions.cs
New file

```cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace Microsoft.AspNetCore.Routing;

internal static class LoginLogoutEndpointRouteBuilderExtensions
{
    internal static IEndpointConventionBuilder MapLoginAndLogout(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("");

        group.MapGet("/login", (string? returnUrl) => TypedResults.Challenge(GetAuthProperties(returnUrl)))
            .AllowAnonymous();

        // Sign out of the Cookie and OIDC handlers. If you do not sign out with the OIDC handler,
        // the user will automatically be signed back in the next time they visit a page that requires authentication
        // without being able to choose another account.
        group.MapPost("/logout", ([FromForm] string? returnUrl) => TypedResults.SignOut(GetAuthProperties(returnUrl),
            [CookieAuthenticationDefaults.AuthenticationScheme, "MicrosoftOidc"]));

        return group;
    }

    private static AuthenticationProperties GetAuthProperties(string? returnUrl)
    {
        // TODO: Use HttpContext.Request.PathBase instead.
        const string pathBase = "/";

        // Prevent open redirects.
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = pathBase;
        }
        else if (!Uri.IsWellFormedUriString(returnUrl, UriKind.Relative))
        {
            returnUrl = new Uri(returnUrl, UriKind.Absolute).PathAndQuery;
        }
        else if (returnUrl[0] != '/')
        {
            returnUrl = $"{pathBase}{returnUrl}";
        }

        return new AuthenticationProperties { RedirectUri = returnUrl };
    }
}
```

## /Components/Pages/_Imports.razor
Add to the bottom:
```cs
@using Microsoft.AspNetCore.Authorization
@using Microsoft.AspNetCore.Components.Authorization
```

## /Referring to user data in code

In Blazor/Razor pages
```cs
@using System.Security.Claims

<AuthorizeView>
     <Authorized>
         <h1>Hello, @context.User.Identity.Name!</h1>

         <p>
            Your claims are:

            <table class="table">
                <thead>
                    <tr>
                        <th>Claim Label</th>
                        <th>Claim Value</th>
                        <th>Claim Issuer</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach(Claim claim in context.User.Claims) 
                    {
                        <tr>
                            <td>@(claim.Type)</td>
                            <td>@(claim.Value.ToString())</td>
                            <td>@(claim.Issuer)</td>
                        </tr>
                    }
                </tbody>
            </table>
         </p>
  
     </Authorized>
     <NotAuthorized>
         <p>Not Authorized</p>
     </NotAuthorized>
 </AuthorizeView>
```

# How to get group memberships in your claims
Groups are not included in claims by default (with Azure/Entra anyway).

 - Go to https://portal.azure.com
 - Go to Entra ID
 - On the left find and click **App Registrations**
 - Find your app that you set up and click into it
 - On the left menu find **Manifest** and click into it
 - Find the line that says `groupMembershipClaims": null,` and change this to `groupMembershipClaims": "SecurityGroup",`

This will have the claims include group memberships *as Azure/Entra ObjectIDs*. You'll want to iterate through the list of claims where the claim type is `groups`, and compare ObjectIds to see if a user is a member of a specific group.

Users will need to log in again for the group claims to show up. If you are testing, you may want to open a new private browser tab and log in again to see them.
