// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using System.Collections.Generic;

namespace Aguacongas.Identity.RavenDb
{
    public class RoleData
    {
        public string Id { get; set; }

        public string RoleId { get; set; }

        public List<string> ClaimIds { get; private set; } = new List<string>();
    }
}
