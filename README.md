# Identity.RavenDb
[ASP.NET Identity](https://github.com/aspnet/AspNetCore/tree/master/src/Identity) RavenDb Provider

[![Build status](https://ci.appveyor.com/api/projects/status/mx5j6q52nrfo4eu5?svg=true)](https://ci.appveyor.com/project/aguacongas/identity-ravendb)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Aguafrommars_Identity.RavenDb&metric=alert_status)](https://sonarcloud.io/dashboard?id=Aguafrommars_Identity.RavenDb)

Nuget packages
--------------
|Aguacongas.Identity.RavenDb|
|:------:|
|[![][Aguacongas.Identity.RavenDb-badge]][Aguacongas.Identity.RavenDb-nuget]|
|[![][Aguacongas.Identity.RavenDb-downloadbadge]][Aguacongas.Identity.RavenDb-nuget]|

[Aguacongas.Identity.RavenDb-badge]: https://img.shields.io/nuget/v/Aguacongas.Identity.RavenDb.svg
[Aguacongas.Identity.RavenDb-downloadbadge]: https://img.shields.io/nuget/dt/Aguacongas.Identity.RavenDb.svg
[Aguacongas.Identity.RavenDb-nuget]: https://www.nuget.org/packages/Aguacongas.Identity.RavenDb/

## Setup

You setup RavenDb stores using one `AddRavenDbStores` extension method

You can setup RavenDb stores using the current IDocumentStore:

```cs
services.AddSingleton(p => new DocumentStore
{
    Urls = new[] { "https://a.ravendb.local" },
    Database = "Identity"
}.SetFindIdentityPropertyForIdentityModel() // REQUIRED, Identity model identifiers are not computed by the database but the store
.Initialize());
services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
        .AddRavenDbStores(); 
```

Or with a `Func<IServiceProvider, IDocumentStore>` creating the `IDocumentStore` :

```cs
var documentStore = new DocumentStore
{
    Urls = new[] { "https://a.ravendb.local" },
    Database = "Identity"
}.SetFindIdentityPropertyForIdentityModel() // REQUIRED, Identity model identifiers are not computed by the database but the store
.Initialize();

services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
    .AddRavenDbStores(p => documentStore);
```

Both methods can take a `string dataBase` parameter to specify the RavenDb database to use:

```cs
services.AddIdentity<IdentityUser, IdentityRole>()
    .AddRedisStores(dataBase: "Identity")
    .AddDefaultTokenProviders();
```

> Your user and role class must be `IdentityUser` and `IdentityRole` or derived.

## Sample

The [IdentitySample](samples/IdentitySample) is a dotnet webapp with individual authentication using a RavenDb database.  

## Tests

This library is tested using [Microsoft.AspNetCore.Identity.Specification.Tests](https://www.nuget.org/packages/Microsoft.AspNetCore.Identity.Specification.Tests/), the shared test suite for Asp.Net Identity Core store implementations.  