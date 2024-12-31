// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Raven.Client.Documents;
using Raven.Embedded;
using Raven.TestDriver;
using System.Runtime.CompilerServices;

namespace Aguacongas.Identity.RavenDb.IntegrationTest
{
    public class RavenDbTestFixture
    {
        readonly IDocumentStore _store;
        public IDocumentStore Store => _store;


        public RavenDbTestFixture()
        {
             _store = new RavenDbTestDriverWrapper().GetDocumentStore();
        }

        class RavenDbTestDriverWrapper : RavenTestDriver
        {
            static RavenDbTestDriverWrapper()
            {
                var testServerOptions = new TestServerOptions();
                testServerOptions.Licensing.ThrowOnInvalidOrMissingLicense = false;
                ConfigureServer(testServerOptions);
            }

            public new IDocumentStore GetDocumentStore(GetDocumentStoreOptions options = null, [CallerMemberName] string database = null)
                => base.GetDocumentStore(options, database);

            protected override void PreInitialize(IDocumentStore documentStore)
            {
                documentStore.SetFindIdentityPropertyForIdentityModel();
                base.PreInitialize(documentStore);
            }
        }
    }
}
