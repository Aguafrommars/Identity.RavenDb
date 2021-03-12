// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using System.Collections.Generic;

namespace Aguacongas.Identity.RavenDb
{
    public class RoleData
    {
        public string Id { get; set; }

        public virtual string RoleId { get; set; }

        public virtual List<string> ClaimIds { get; private set; } = new List<string>();
    }
}
