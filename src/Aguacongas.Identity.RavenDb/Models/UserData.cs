// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;

namespace Aguacongas.Identity.RavenDb
{
    public class UserData<TKey, TUser, TUserClaim, TUserLogin, TUserToken> 
        where TKey: IEquatable<TKey>
        where TUser: IdentityUser<TKey>
        where TUserClaim : IdentityUserClaim<TKey>
        where TUserLogin : IdentityUserLogin<TKey>
        where TUserToken : IdentityUserToken<TKey>
    {
        public string Id { get; set; }

        public virtual TUser User { get; set; }

        public virtual List<TUserClaim> Claims { get; private set; } = new List<TUserClaim>();

        public virtual List<TUserLogin> Logins { get; private set; } = new List<TUserLogin>();
    }
}
