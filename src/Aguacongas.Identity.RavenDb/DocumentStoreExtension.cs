using Aguacongas.Identity.RavenDb;
using Microsoft.AspNetCore.Identity;
using System;
using System.Reflection;

namespace Raven.Client.Documents
{
    public static class DocumentStoreExtension
    {
        public static IDocumentStore SetFindIdentityPropertyForIdentityModel(this IDocumentStore store)
        {
            var findId = store.Conventions.FindIdentityProperty;
            store.Conventions.FindIdentityProperty = memberInfo => SetConventions(memberInfo, findId);
            return store;
        }

        private static bool SetConventions(MemberInfo memberInfo, Func<MemberInfo, bool> findId)
        {
            if (memberInfo.DeclaringType == typeof(UserData))
            {
                return false;
            }
            if (memberInfo.DeclaringType == typeof(RoleData))
            {
                return false;
            }            
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityUser<>)))
            {
                return false;
            }
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityUserClaim<>)))
            {
                return false;
            }
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityUserRole<>)))
            {
                return false;
            }
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityUserLogin<>)))
            {
                return false;
            }
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityUserToken<>)))
            {
                return false;
            }
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityRole<>)))
            {
                return false;
            }
            if (IsSubclassOf(memberInfo.DeclaringType, typeof(IdentityRoleClaim<>)))
            {
                return false;
            }

            return findId(memberInfo);
        }

        private static bool IsSubclassOf(Type type, Type baseType)
        {
            if (type == null || baseType == null || type == baseType)
            {
                return false;
            }

            if (!baseType.IsGenericType)
            {
                if (!type.IsGenericType)
                {
                    return type.IsSubclassOf(baseType);
                }
            }
            else
            {
                baseType = baseType.GetGenericTypeDefinition();
            }

            var objectType = typeof(object);
            while (type != objectType && type != null)
            {
                var curentType = type.IsGenericType ? type.GetGenericTypeDefinition() : type;
                if (curentType == baseType)
                {
                    return true;
                }

                type = type.BaseType;
            }

            return false;
        }
    }
}
