// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using Raven.TestDriver;
using System.Runtime.CompilerServices;

namespace Aguacongas.Identity.RavenDb.IntegrationTest
{
    public class RavenDbTestFixture
    {
        IDocumentStore _store;
        public IDocumentStore Store => _store;


        public RavenDbTestFixture()
        {
             _store = new RavenDbTestDriverWrapper().GetDocumentStore();
            //_store = new DocumentStore
            //{
            //    Urls = new[]
            //    {
            //        "https://a.ravendb.local",
            //        "https://b.ravendb.local",
            //        "https://c.ravendb.local"
            //    },
            //    Certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(@"C:\Projects\Perso\helm-charts\cluster.admin.cert\cluster.admin.client.certificate.pfx", "p@$$w0rd"),
            //    Database = "Test"
            //}.Initialize();
        }

        class RavenDbTestDriverWrapper : RavenTestDriver
        {
            public new IDocumentStore GetDocumentStore(GetDocumentStoreOptions options = null, [CallerMemberName] string database = null)
                => base.GetDocumentStore(options, database);
        }
    }
}
