namespace Aguacongas.Identity.RavenDb
{
    public class UserLoginIndex
    {
        public string Id { get; set; }

        public string UserId { get; set; }

        public string LoginProvider { get; set; }

        public string ProviderKey { get; set; }
    }
}
