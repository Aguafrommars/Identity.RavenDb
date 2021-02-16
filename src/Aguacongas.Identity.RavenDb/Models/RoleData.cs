// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Aguacongas.Identity.RavenDb
{
    [SuppressMessage("Major Code Smell", "S2436:Types and methods should not have too many generic parameters", Justification = "All are needed")]
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
