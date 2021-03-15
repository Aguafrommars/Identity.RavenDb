// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using Raven.Client.Documents.Session;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Aguacongas.Identity.RavenDb
{
    /// <summary>
    /// Represents a new instance of a persistence store for users, using the default implementation
    /// of <see cref="IdentityUser{string}"/> with a string as a primary key.
    /// </summary>
    public class UserStore : UserStore<IdentityUser<string>>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore"/>.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserStore(IAsyncDocumentSession session, UserOnlyStore<string> userOnlyStore, IdentityErrorDescriber describer = null) : base(session, userOnlyStore, describer) { }
    }

    /// <summary>
    /// Creates a new instance of a persistence store for the specified user type.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    public class UserStore<TUser> : UserStore<TUser, IdentityRole>
        where TUser : IdentityUser<string>, new()
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser}"/>.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserStore(IAsyncDocumentSession session, UserOnlyStore<TUser, string> userOnlyStore, IdentityErrorDescriber describer = null) : base(session, userOnlyStore, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    public class UserStore<TUser, TRole> : UserStore<TUser, string, TRole, IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityUserToken<string>, IdentityRoleClaim<string>>
        where TUser : IdentityUser<string>
        where TRole : IdentityRole<string>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TContext, string}"/>.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserStore(IAsyncDocumentSession session, UserOnlyStore<TUser, string> userOnlyStore, IdentityErrorDescriber describer = null) : base(session, userOnlyStore, describer) { }
    }


    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    [SuppressMessage("Major Code Smell", "S2436:Types and methods should not have too many generic parameters", Justification = "Identity store implementation")]
    public class UserStore<TUser, TRole, TKey> : UserStore<TUser, TKey, TRole, IdentityUserClaim<TKey>, IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>, IdentityRoleClaim<TKey>>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TContext, string}"/>.
        /// </summary>
        /// <param name="db">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserStore(IAsyncDocumentSession session, UserOnlyStore<TUser, TKey> userOnlyStore, IdentityErrorDescriber describer = null) : base(session, userOnlyStore, describer) { }
    }


    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TRole">The type representing a role.</typeparam>
    /// <typeparam name="TUserClaim">The type representing a claim.</typeparam>
    /// <typeparam name="TUserRole">The type representing a user role.</typeparam>
    /// <typeparam name="TUserLogin">The type representing a user external login.</typeparam>
    /// <typeparam name="TUserToken">The type representing a user token.</typeparam>
    /// <typeparam name="TRoleClaim">The type representing a role claim.</typeparam>
    [SuppressMessage("Major Code Smell", "S2436:Types and methods should not have too many generic parameters", Justification = "All are needed")]
    public class UserStore<TUser, TKey, TRole, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim> :
        RavenDbUserStoreBase<TUser, TKey, TRole, TUserClaim, TUserRole, TUserLogin, TUserToken, TRoleClaim>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TRole : IdentityRole<TKey>
        where TUserClaim : IdentityUserClaim<TKey>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserToken : IdentityUserToken<TKey>, new()
        where TRoleClaim : IdentityRoleClaim<TKey>, new()
    {
        private readonly IAsyncDocumentSession _session;
        private readonly UserOnlyStore<TUser, TKey, TUserClaim, TUserLogin, TUserToken> _userOnlyStore;

        /// <summary>
        /// A navigation property for the users the store contains.
        /// </summary>
        public override IQueryable<TUser> Users => _userOnlyStore.Users;

        /// <summary>
        /// Creates a new instance of the store.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
        public UserStore(IAsyncDocumentSession session, UserOnlyStore<TUser, TKey, TUserClaim, TUserLogin, TUserToken> userOnlyStore, IdentityErrorDescriber describer = null) : base(describer ?? new IdentityErrorDescriber())
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
            _userOnlyStore = userOnlyStore ?? throw new ArgumentNullException(nameof(userOnlyStore));
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
        public override Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
            => _userOnlyStore.CreateAsync(user, cancellationToken);

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
            => _userOnlyStore.UpdateAsync(user, cancellationToken);

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public override Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
            => _userOnlyStore.DeleteAsync(user, cancellationToken);

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public override Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
            => _userOnlyStore.FindByIdAsync(userId, cancellationToken);

        /// <summary>
        /// Finds and returns a user, if any, who has the specified normalized user name.
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
        /// </returns>
        public override Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
            => _userOnlyStore.FindByNameAsync(normalizedUserName, cancellationToken);

        /// <summary>
        /// Adds the given <paramref name="roleName"/> to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the role to.</param>
        /// <param name="roleName">The role to add.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public async override Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNullOrEmpty(roleName, nameof(roleName));

            var userId = ConvertIdToString(user.Id);
            var roleEntity = await FindRoleAsync(roleName, cancellationToken)
                .ConfigureAwait(false);

            if (roleEntity == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "RoleNotFound {0}", roleName));
            }

            var userRole = new TUserRole
            {
                RoleId = roleEntity.Id,
                UserId = user.Id
            };

            await _session.StoreAsync(userRole, $"userrole/{roleName}@{userId}", cancellationToken).ConfigureAwait(false);
            await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Removes the given <paramref name="roleName"/> from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the role from.</param>
        /// <param name="roleName">The role to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public async override Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNullOrEmpty(roleName, nameof(roleName));

            var roleEntity = await FindRoleAsync(roleName, cancellationToken)
                .ConfigureAwait(false);
            if (roleEntity == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "RoleNotFound {0}", roleName));
            }

            var userId = ConvertIdToString(user.Id);

            var userRole = await _session.LoadAsync<TUserRole>($"userrole/{roleName}@{userId}", cancellationToken).ConfigureAwait(false);
            _session.Delete(userRole);
            await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }


        /// <summary>
        /// Retrieves the roles the specified <paramref name="user"/> is a member of.
        /// </summary>
        /// <param name="user">The user whose roles should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the roles the user is a member of.</returns>
        public override async Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            var userId = ConvertIdToString(user.Id);

            var userRoleList = await _session.Advanced.LoadStartingWithAsync<TUserRole>(idPrefix: "userrole/", matches: $"*@{userId}", token: cancellationToken).ConfigureAwait(false);
            var roles = await _session.LoadAsync<TRole>(userRoleList.Select(r => $"role/{ConvertIdToString(r.RoleId)}"), cancellationToken).ConfigureAwait(false);
            return roles.Where(r => r.Value != null).Select(r => r.Value.Name).ToList();
        }

        /// <summary>
        /// Returns a flag indicating if the specified user is a member of the give <paramref name="roleName"/>.
        /// </summary>
        /// <param name="user">The user whose role membership should be checked.</param>
        /// <param name="roleName">The role to check membership of</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> containing a flag indicating if the specified user is a member of the given group. If the 
        /// user is a member of the group the returned value with be true, otherwise it will be false.</returns>
        public override async Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNullOrEmpty(roleName, nameof(roleName));

            var userId = ConvertIdToString(user.Id);
            var userRole = await _session.LoadAsync<TUserRole>($"userrole/{roleName}@{userId}", cancellationToken).ConfigureAwait(false);
            return userRole != null;
        }

        /// <summary>
        /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose claims should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a user.</returns>
        public override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
            => _userOnlyStore.GetClaimsAsync(user, cancellationToken);

        /// <summary>
        /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claim to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
            => _userOnlyStore.AddClaimsAsync(user, claims, cancellationToken);

        /// <summary>
        /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim replace.</param>
        /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
            => _userOnlyStore.ReplaceClaimAsync(user, claim, newClaim, cancellationToken);

        /// <summary>
        /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the claims from.</param>
        /// <param name="claims">The claim to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
            => _userOnlyStore.RemoveClaimsAsync(user, claims, cancellationToken);

        /// <summary>
        /// Adds the <paramref name="login"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the login to.</param>
        /// <param name="login">The login to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task AddLoginAsync(TUser user, UserLoginInfo login,
            CancellationToken cancellationToken = default)
            => _userOnlyStore.AddLoginAsync(user, login, cancellationToken);

        /// <summary>
        /// Removes the <paramref name="loginProvider"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the login from.</param>
        /// <param name="loginProvider">The login to remove from the user.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
            => _userOnlyStore.RemoveLoginAsync(user, loginProvider, providerKey, cancellationToken);

        /// <summary>
        /// Retrieves the associated logins for the specified <param ref="user"/>.
        /// </summary>
        /// <param name="user">The user whose associated logins to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        public override Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
            => _userOnlyStore.GetLoginsAsync(user, cancellationToken);

        /// <summary>
        /// Retrieves the user associated with the specified login provider and login provider key.
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        public override Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
            => _userOnlyStore.FindByLoginAsync(loginProvider, providerKey, cancellationToken);

        /// <summary>
        /// Gets the user, if any, associated with the specified, normalized email address.
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        public override Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
            => _userOnlyStore.FindByEmailAsync(normalizedEmail, cancellationToken);

        /// <summary>
        /// Retrieves all users with the specified claim.
        /// </summary>
        /// <param name="claim">The claim whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that contain the specified claim. 
        /// </returns>
        public override Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
            => _userOnlyStore.GetUsersForClaimAsync(claim, cancellationToken);

        /// <summary>
        /// Retrieves all users in the specified role.
        /// </summary>
        /// <param name="roleName">The role whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that are in the specified role. 
        /// </returns>
        public async override Task<IList<TUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNullOrEmpty(roleName, nameof(roleName));

            var userRoleList = await _session.Advanced.LoadStartingWithAsync<TUserRole>($"userrole/{roleName}@", token: cancellationToken).ConfigureAwait(false);
            var userList = await _session.LoadAsync<TUser>(userRoleList.Select(ur => $"user/{ConvertIdToString(ur.UserId)}"), cancellationToken).ConfigureAwait(false);

            return userList.Where(u => u.Value != null).Select(u => u.Value).ToList();
        }

        /// <summary>
        /// Sets the given normalized name for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="normalizedName">The normalized name to set.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default)
             => _userOnlyStore.SetNormalizedUserNameAsync(user, normalizedName, cancellationToken);

        /// <summary>
        /// Sets the normalized email for the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user whose email address to set.</param>
        /// <param name="normalizedEmail">The normalized email to set for the specified <paramref name="user"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public override Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default)
            => _userOnlyStore.SetNormalizedEmailAsync(user, normalizedEmail, cancellationToken);

        /// <summary>
        /// Sets the token value for a particular user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="value">The value of the token.</param>
        /// <param name="cancellationToken">The <see cref="T:CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:Task" /> that represents the asynchronous operation.
        /// </returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
            => _userOnlyStore.SetTokenAsync(user, loginProvider, name, value, cancellationToken);

        /// <summary>
        /// Deletes a token for a user.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="T:CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:Task" /> that represents the asynchronous operation.
        /// </returns>
        /// <exception cref="NotImplementedException"></exception>
        public override Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
            => _userOnlyStore.RemoveTokenAsync(user, loginProvider, name, cancellationToken);

        /// <summary>
        /// Returns the token value.
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="loginProvider">The authentication provider for the token.</param>
        /// <param name="name">The name of the token.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.
        /// </returns>
        /// <exception cref="System.NotImplementedException"></exception>
        public override Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
            => _userOnlyStore.GetTokenAsync(user, loginProvider, name, cancellationToken);

        /// <summary>
        /// Return a role with the normalized name if it exists.
        /// </summary>
        /// <param name="normalizedRoleName">The normalized role name.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The role if it exists.</returns>
        protected override async Task<TRole> FindRoleAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            var index = await _session.Include<RoleNameIndex>(i => i.RoleId)
                .LoadAsync<RoleNameIndex>($"rolename/{normalizedRoleName}", cancellationToken)
                .ConfigureAwait(false);

            if (index == null)
            {
                return null;
            }

            return await _session.LoadAsync<TRole>(index.RoleId, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Return a user with the matching userId if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user if it exists.</returns>
        protected override Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken)
            => FindByIdAsync(userId.ToString(), cancellationToken);
        
        
        
        protected override void Dispose(bool disposed)
        {
            base.Dispose(disposed);
            _userOnlyStore.Dispose();
        }

        protected virtual async Task<TRole> FindRoleByIdAsync(string id, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return await _session.LoadAsync<TRole>($"role/{id}", cancellationToken).ConfigureAwait(false);
        }

        private static void AssertNotNullOrEmpty(string p, string pName)
        {
            if (string.IsNullOrWhiteSpace(p))
            {
                throw new ArgumentNullException(pName);
            }
        }
    }

}
