// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2021 Olivier Lefebvre
using Aguacongas.Identity.RavenDb;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using System;
using System.Reflection;

namespace Microsoft.Extensions.DependencyInjection
{

    /// <summary>
    /// Contains extension methods to <see cref="IdentityBuilder"/> for adding entity framework stores.
    /// </summary>
    public static class IdentityBuilderExtensions
    {
        /// <summary>
        /// Adds an RavenDb implementation of identity stores.
        /// </summary>
        /// <param name="builder">The <see cref="IdentityBuilder" /> instance this method extends.</param>
        /// <param name="getDocumentStore"><see cref="IDocumentStore" /> factory function returning the RavenDb document store to use</param>
        /// <param name="dataBase">The data base.</param>
        /// <returns>
        /// The <see cref="IdentityBuilder" /> instance this method extends.
        /// </returns>
        public static IdentityBuilder AddRavenDbStores(this IdentityBuilder builder, Func<IServiceProvider, IDocumentStore> getDocumentStore = null, string dataBase = null)
        {
            if (getDocumentStore == null)
            {
                getDocumentStore = p => p.GetRequiredService<IDocumentStore>();
            }

            AddStores(builder.Services, builder.UserType, builder.RoleType, p =>
            {
                var session = getDocumentStore(p).OpenAsyncSession(new SessionOptions
                {
                    Database = dataBase
                });
                var adv = session.Advanced;
                adv.UseOptimisticConcurrency = true;
                adv.MaxNumberOfRequestsPerSession = int.MaxValue;
                return session;
            });

            return builder;
        }

        private static void AddStores(IServiceCollection services, Type userType, Type roleType, Func<IServiceProvider, IAsyncDocumentSession> getSession)
        {
            var identityUserType = FindGenericBaseType(userType, typeof(IdentityUser<>));
            if (identityUserType == null)
            {
                throw new InvalidOperationException("AddEntityFrameworkStores can only be called with a user that derives from IdentityUser<TKey>.");
            }

            var keyType = identityUserType.GenericTypeArguments[0];
        
            var userOnlyStoreType = typeof(UserOnlyStore<,>).MakeGenericType(userType, keyType);

            if (roleType != null)   
            {
                var identityRoleType = FindGenericBaseType(roleType, typeof(IdentityRole<>));
                if (identityRoleType == null)
                {
                    throw new InvalidOperationException("AddEntityFrameworkStores can only be called with a role that derives from IdentityRole<TKey>.");
                }

                var userStoreType = typeof(UserStore<,,>).MakeGenericType(userType, roleType, keyType);
                var roleStoreType = typeof(RoleStore<,>).MakeGenericType(roleType, keyType);

                services.TryAddScoped(typeof(UserOnlyStore<,>).MakeGenericType(userType, keyType), provider => CreateStoreInstance(userOnlyStoreType, getSession(provider), provider.GetService<IdentityErrorDescriber>()));
                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), provider => userStoreType.GetConstructor(new Type[] { typeof(IAsyncDocumentSession), userOnlyStoreType, typeof(IdentityErrorDescriber) })
                    .Invoke(new object[] { getSession(provider), provider.GetService(userOnlyStoreType), provider.GetService<IdentityErrorDescriber>() }));
                services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), provider => CreateStoreInstance(roleStoreType, getSession(provider), provider.GetService<IdentityErrorDescriber>()));
            }
            else
            {   // No Roles
                services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), provider => CreateStoreInstance(userOnlyStoreType, getSession(provider), provider.GetService<IdentityErrorDescriber>()));
            }
        }

        private static object CreateStoreInstance(Type storeType, IAsyncDocumentSession session, IdentityErrorDescriber errorDescriber)
        {
            var constructor = storeType.GetConstructor(new Type[] { typeof(IAsyncDocumentSession), typeof(IdentityErrorDescriber)});
            return constructor.Invoke(new object[] { session, errorDescriber });
        }

        private static TypeInfo FindGenericBaseType(Type currentType, Type genericBaseType)
        {
            var type = currentType;
            while (type != null)
            {
                var typeInfo = type.GetTypeInfo();
                var genericType = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
                if (genericType != null && genericType == genericBaseType)
                {
                    return typeInfo;
                }
                type = type.BaseType;
            }
            return null;
        }
    }
}