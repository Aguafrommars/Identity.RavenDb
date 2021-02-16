// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;

namespace Aguacongas.Identity.RavenDb
{
    public class RoleData<TKey, TRole, TRoleClaims> 
        where TKey: IEquatable<TKey>
        where TRole : IdentityRole<TKey>
        where TRoleClaims: IdentityRoleClaim<TKey>
    {
        public string Id { get; set; }

        public virtual TRole Role { get; set; }

        public virtual List<TRoleClaims> Claims { get; private set; } = new List<TRoleClaims>();
    }
}
