// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using Raven.Client.Exceptions;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Aguacongas.Identity.RavenDb
{
    /// <summary>
    /// Represents a new instance of a persistence store for <see cref="IdentityUser"/>.
    /// </summary>
    public class UserOnlyStore : UserOnlyStore<string>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TKey}"/>.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserOnlyStore(IAsyncDocumentSession session, IdentityErrorDescriber describer = null) : base(session, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for <see cref="IdentityUser"/>.
    /// </summary>
    public class UserOnlyStore<TKey>: UserOnlyStore<IdentityUser<TKey>, TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TKey}"/>.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserOnlyStore(IAsyncDocumentSession session, IdentityErrorDescriber describer = null) : base(session, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    public class UserOnlyStore<TUser, TKey> : UserOnlyStore<TUser, TKey, IdentityUserClaim<TKey>, IdentityUserLogin<TKey>, IdentityUserToken<TKey>>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
    {
        /// <summary>
        /// Constructs a new instance of <see cref="UserStore{TUser, TRole, TKey}"/>.
        /// </summary>
        /// <param name="db">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/>.</param>
        public UserOnlyStore(IAsyncDocumentSession session, IdentityErrorDescriber describer = null) : base(session, describer) { }
    }

    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TUserClaim">The type representing a claim.</typeparam>
    /// <typeparam name="TUserLogin">The type representing a user external login.</typeparam>
    /// <typeparam name="TUserToken">The type representing a user token.</typeparam>
    [SuppressMessage("Major Code Smell", "S2436:Types and methods should not have too many generic parameters", Justification = "All are needed")]
    public class UserOnlyStore<TUser, TKey, TUserClaim, TUserLogin, TUserToken> :
        RavenDbUserStoreBase<TUser, TKey, TUserClaim, TUserLogin, TUserToken>,
        IUserLoginStore<TUser>,
        IUserClaimStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IUserAuthenticationTokenStore<TUser>,
        IUserAuthenticatorKeyStore<TUser>,
        IUserTwoFactorRecoveryCodeStore<TUser>
        where TUser : IdentityUser<TKey>
        where TKey : IEquatable<TKey>
        where TUserClaim : IdentityUserClaim<TKey>, new()
        where TUserLogin : IdentityUserLogin<TKey>, new()
        where TUserToken : IdentityUserToken<TKey>, new()
    {
        private readonly IAsyncDocumentSession _session;

        /// <summary>
        /// A navigation property for the users the store contains.
        /// </summary>
        public override IQueryable<TUser> Users
        => _session.Query<UserData<TKey, TUser, TUserClaim, TUserLogin>>()
            .Select(d => d.User)
            .ToListAsync().ConfigureAwait(false).GetAwaiter().GetResult().AsQueryable();

        /// <summary>
        /// Creates a new instance of the store.
        /// </summary>
        /// <param name="session">The document session.</param>
        /// <param name="describer">The <see cref="IdentityErrorDescriber"/> used to describe store errors.</param>
        public UserOnlyStore(IAsyncDocumentSession session, IdentityErrorDescriber describer = null) : base(describer ?? new IdentityErrorDescriber())
        {
            _session = session ?? throw new ArgumentNullException(nameof(session));
        }

        /// <summary>
        /// Creates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to create.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the creation operation.</returns>
        public async override Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            var userId = ConvertIdToString(user.Id);

            var data = new UserData<TKey, TUser, TUserClaim, TUserLogin>
            {
                Id = $"user/{userId}",
                User = user
            };
            await _session.StoreAsync(data, cancellationToken).ConfigureAwait(false);
            await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        /// <summary>
        /// Updates the specified <paramref name="user"/> in the user store.
        /// </summary>
        /// <param name="user">The user to update.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public async override Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            var userId = ConvertIdToString(user.Id);
            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>($"user/{userId}", cancellationToken).ConfigureAwait(false);

            data.User = user;

            try
            {
                await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        /// <summary>
        /// Deletes the specified <paramref name="user"/> from the user store.
        /// </summary>
        /// <param name="user">The user to delete.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation, containing the <see cref="IdentityResult"/> of the update operation.</returns>
        public async override Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            var userId = ConvertIdToString(user.Id);
            _session.Delete($"user/{userId}");
            _session.Delete($"username/{user.NormalizedUserName}");

            try
            {
                await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (ConcurrencyException)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        public override async Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            if (user.NormalizedUserName == normalizedName)
            {
                return;
            }

            if (!string.IsNullOrEmpty(user.NormalizedUserName))
            {
                _session.Delete($"username/{user.NormalizedUserName}");
            }
            
            user.NormalizedUserName = normalizedName;

            if (string.IsNullOrEmpty(normalizedName))
            {
                return;
            }

            await _session.StoreAsync(new UserNameIndex
            {
                Id = $"username/{normalizedName}",
                NormalizedUserName = normalizedName,
                UserId = $"user/{ConvertIdToString(user.Id)}"
            }, cancellationToken).ConfigureAwait(false);
        }

        public override async Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            if (user.NormalizedEmail == normalizedEmail)
            {
                return;
            }

            if (!string.IsNullOrEmpty(user.NormalizedEmail))
            {
                _session.Delete($"useremail/{user.NormalizedEmail}");
            }

            var userId = ConvertIdToString(user.Id);

            user.NormalizedEmail = normalizedEmail;

            if (string.IsNullOrEmpty(normalizedEmail))
            {
                return;
            }

            var index = await _session.LoadAsync<UserEMailIndex>($"useremail/{normalizedEmail}", cancellationToken).ConfigureAwait(false);
            if (index == null)
            {
                index = new UserEMailIndex
                {
                    Id = $"useremail/{normalizedEmail}",
                    UserId= $"user/{userId}"
                };
                await _session.StoreAsync(index, cancellationToken).ConfigureAwait(false);
                return;
            }

            index.UserId = $"user/{userId}";
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified <paramref name="userId"/>.
        /// </summary>
        /// <param name="userId">The user ID to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="userId"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>($"user/{userId}", cancellationToken).ConfigureAwait(false);
            return data?.User;
        }

        /// <summary>
        /// Finds and returns a user, if any, who has the specified normalized user name.
        /// </summary>
        /// <param name="normalizedUserName">The normalized user name to search for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> that represents the asynchronous operation, containing the user matching the specified <paramref name="normalizedUserName"/> if it exists.
        /// </returns>
        public override async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var index = await _session
                .Include<UserNameIndex>(i => i.UserId)
                .LoadAsync<UserNameIndex>($"username/{normalizedUserName}", cancellationToken).ConfigureAwait(false);
            if (index == null)
            {
                return null;
            }

            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>(index.UserId, cancellationToken).ConfigureAwait(false);
            return data.User;
        }

        /// <summary>
        /// Get the claims associated with the specified <paramref name="user"/> as an asynchronous operation.
        /// </summary>
        /// <param name="user">The user whose claims should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="Task{TResult}"/> that contains the claims granted to a user.</returns>
        public async override Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            var claimList = await GetUserClaimsAsync(user, cancellationToken).ConfigureAwait(false);
            return claimList
                .Select(c => c.ToClaim())
                .ToList();
        }

        /// <summary>
        /// Adds the <paramref name="claims"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the claim to.</param>
        /// <param name="claims">The claim to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNull(claims, nameof(claims));

            var claimList = await GetUserClaimsAsync(user, cancellationToken).ConfigureAwait(false);
            claimList.AddRange(claims.Select(c => CreateUserClaim(user, c)));
        }

        /// <summary>
        /// Replaces the <paramref name="claim"/> on the specified <paramref name="user"/>, with the <paramref name="newClaim"/>.
        /// </summary>
        /// <param name="user">The user to replace the claim on.</param>
        /// <param name="claim">The claim replace.</param>
        /// <param name="newClaim">The new claim replacing the <paramref name="claim"/>.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public async override Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNull(claim, nameof(claim));
            AssertNotNull(newClaim, nameof(newClaim));

            var claimList = await GetUserClaimsAsync(user, cancellationToken).ConfigureAwait(false);
            foreach (var uc in claimList)
            {
                if (uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value)
                {
                    uc.ClaimType = newClaim.Type;
                    uc.ClaimValue = newClaim.Value;
                }
            }
        }

        /// <summary>
        /// Removes the <paramref name="claims"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the claims from.</param>
        /// <param name="claims">The claim to remove.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public async override Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNull(claims, nameof(claims));

            var claimList = await GetUserClaimsAsync(user, cancellationToken).ConfigureAwait(false);
            foreach (var claim in claims)
            {
                claimList.RemoveAll(uc => uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value);
            }
        }

        /// <summary>
        /// Adds the <paramref name="login"/> given to the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to add the login to.</param>
        /// <param name="login">The login to add to the user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task AddLoginAsync(TUser user, UserLoginInfo login,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));
            AssertNotNull(login, nameof(login));

            var userId = ConvertIdToString(user.Id);
            await _session.StoreAsync(new UserLoginIndex
            {
                Id = $"userlogin/{login.LoginProvider}-{login.ProviderKey}",
                UserId = $"user/{userId}",
                LoginProvider = login.LoginProvider,
                ProviderKey = login.ProviderKey
            }).ConfigureAwait(false);
            
            var logins = await GetUserLoginsAsync(userId, cancellationToken).ConfigureAwait(false);
            logins.Add(CreateUserLogin(user, login));
        }

        /// <summary>
        /// Removes the <paramref name="loginProvider"/> given from the specified <paramref name="user"/>.
        /// </summary>
        /// <param name="user">The user to remove the login from.</param>
        /// <param name="loginProvider">The login to remove from the user.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="Task"/> that represents the asynchronous operation.</returns>
        public override async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            _session.Delete($"userlogin/{loginProvider}-{providerKey}");

            var userId = ConvertIdToString(user.Id);

            var logins = await GetUserLoginsAsync(userId, cancellationToken).ConfigureAwait(false);
            logins.RemoveAll(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
        }

        /// <summary>
        /// Retrieves the associated logins for the specified <param ref="user"/>.
        /// </summary>
        /// <param name="user">The user whose associated logins to retrieve.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing a list of <see cref="UserLoginInfo"/> for the specified <paramref name="user"/>, if any.
        /// </returns>
        public async override Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(user, nameof(user));

            var userId = ConvertIdToString(user.Id);

            var logins = await GetUserLoginsAsync(userId, cancellationToken).ConfigureAwait(false);
            return logins
                .Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))
                .ToList();
        }

        /// <summary>
        /// Retrieves the user associated with the specified login provider and login provider key.
        /// </summary>
        /// <param name="loginProvider">The login provider who provided the <paramref name="providerKey"/>.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> for the asynchronous operation, containing the user, if any which matched the specified login provider and key.
        /// </returns>
        public override async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var index = await _session.LoadAsync<UserLoginIndex>($"userlogin/{loginProvider}-{providerKey}", cancellationToken).ConfigureAwait(false);
            if (index == null)
            {
                return null;
            }

            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>(index.UserId, cancellationToken).ConfigureAwait(false);
            return data.User;
        }

        /// <summary>
        /// Gets the user, if any, associated with the specified, normalized email address.
        /// </summary>
        /// <param name="normalizedEmail">The normalized email address to return the user for.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The task object containing the results of the asynchronous lookup operation, the user if any associated with the specified normalized email address.
        /// </returns>
        public override async Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var index = await _session.LoadAsync<UserEMailIndex>($"useremail/{normalizedEmail}", cancellationToken).ConfigureAwait(false);
            if (index == null)
            {
                return null;
            }

            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>(index.UserId, cancellationToken).ConfigureAwait(false);
            return data?.User;
        }

        /// <summary>
        /// Retrieves all users with the specified claim.
        /// </summary>
        /// <param name="claim">The claim whose users should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>
        /// The <see cref="Task"/> contains a list of users, if any, that contain the specified claim. 
        /// </returns>
        public async override Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            AssertNotNull(claim, nameof(claim));

            return await _session.Query<UserData<TKey, TUser, TUserClaim, TUserLogin>>()
                .Where(d => d.Claims.Any(c => c.ClaimType == claim.Type && c.ClaimValue == claim.Value))
                .Select(d => d.User)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false);
        }

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
        public override async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var userId = ConvertIdToString(user.Id);
            var token = await _session.LoadAsync<TUserToken>($"usertoken/{userId}-{loginProvider}-{name}", cancellationToken).ConfigureAwait(false);
            if (token == null)
            {
                token = new TUserToken
                {
                    LoginProvider = loginProvider,
                    Name = name,
                    UserId = user.Id,
                    Value = value
                };
                await _session.StoreAsync(token, $"usertoken/{userId}-{loginProvider}-{name}", cancellationToken).ConfigureAwait(false);
            }
            token.Value = value;
            await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

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
        public override async Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var userId = ConvertIdToString(user.Id);
            _session.Delete($"usertoken/{userId}-{loginProvider}-{name}");
            await _session.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

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
        public override async Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var userId = ConvertIdToString(user.Id);

            var token = await _session.LoadAsync<TUserToken>($"usertoken/{userId}-{loginProvider}-{name}", cancellationToken).ConfigureAwait(false);
            return token?.Value;
        }

        /// <summary>
        /// Return a user login with the matching userId, provider, providerKey if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        internal Task<TUserLogin> FindUserLoginInternalAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            return FindUserLoginAsync(userId, loginProvider, providerKey, cancellationToken);
        }

        /// <summary>
        /// Return a user login with  provider, providerKey if it exists.
        /// </summary>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        internal Task<TUserLogin> FindUserLoginInternalAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            return FindUserLoginAsync(loginProvider, providerKey, cancellationToken);
        }

        
        /// <summary>
        /// Return a user with the matching userId if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user if it exists.</returns>
        protected override Task<TUser> FindUserAsync(TKey userId, CancellationToken cancellationToken)
        {
            return FindByIdAsync(userId.ToString(), cancellationToken);
        }

        /// <summary>
        /// Return a user login with the matching userId, provider, providerKey if it exists.
        /// </summary>
        /// <param name="userId">The user's id.</param>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        protected override async Task<TUserLogin> FindUserLoginAsync(string userId, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            var data = await GetUserLoginsAsync(userId, cancellationToken).ConfigureAwait(false);
            if (data != null)
            {
                return data.FirstOrDefault(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey);
            }
            return null;
        }

        /// <summary>
        /// Return a user login with  provider, providerKey if it exists.
        /// </summary>
        /// <param name="loginProvider">The login provider name.</param>
        /// <param name="providerKey">The key provided by the <paramref name="loginProvider"/> to identify a user.</param>
        /// <param name="cancellationToken">The <see cref="CancellationToken"/> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The user login if it exists.</returns>
        protected override Task<TUserLogin> FindUserLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            return _session.Query<UserData<TKey, TUser, TUserClaim, TUserLogin>>()
                .Where(d => d.Logins.Any(l=> l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
                .Select(d => d.Logins.First(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
                .FirstOrDefaultAsync();
        }

        protected virtual async Task<List<TUserClaim>> GetUserClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            var userId = ConvertIdToString(user.Id);
            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>($"user/{userId}", cancellationToken).ConfigureAwait(false);

            return data.Claims;
        }

        protected virtual async Task<List<TUserLogin>> GetUserLoginsAsync(string userId, CancellationToken cancellationToken)
        {
            var data = await _session.LoadAsync<UserData<TKey, TUser, TUserClaim, TUserLogin>>($"user/{userId}", cancellationToken).ConfigureAwait(false);
            return data.Logins;
        }
    }
}
