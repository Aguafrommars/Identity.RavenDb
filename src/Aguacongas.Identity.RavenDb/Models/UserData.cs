// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Aguacongas.Identity.RavenDb
{
    [SuppressMessage("Major Code Smell", "S2436:Types and methods should not have too many generic parameters", Justification = "All are needed")]
    public class UserData<TKey, TUser, TUserClaim, TUserLogin> 
        where TKey: IEquatable<TKey>
        where TUser: IdentityUser<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TUserLogin : IdentityUserLogin<TKey>        
    {
        public string Id { get; set; }

        public virtual TUser User { get; set; }

        public virtual List<TUserClaim> Claims { get; private set; } = new List<TUserClaim>();

        public virtual List<TUserLogin> Logins { get; private set; } = new List<TUserLogin>();
    }
}
