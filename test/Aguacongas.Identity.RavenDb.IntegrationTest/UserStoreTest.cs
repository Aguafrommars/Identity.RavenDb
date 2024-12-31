// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2025 Olivier Lefebvre
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Test;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using Raven.TestDriver;
using System;
using System.Linq.Expressions;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace Aguacongas.Identity.RavenDb.IntegrationTest
{

    public class UserStoreTest : IdentitySpecificationTestBase<TestUser, TestRole>, IClassFixture<RavenDbTestFixture>
    {
        private readonly RavenDbTestFixture _fixture;
        private readonly ITestOutputHelper _testOutputHelper;

        public UserStoreTest(RavenDbTestFixture fixture, ITestOutputHelper testOutputHelper)
        {
            _fixture = fixture;
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public async Task CanUpdateUserMultipleTime()
        {
            var manager = CreateManager();
            var user = CreateTestUser();
            IdentityResultAssert.IsSuccess(await manager.CreateAsync(user));
            user = await manager.FindByNameAsync(user.UserName);
            user.PhoneNumber = "+41123456789";
            IdentityResultAssert.IsSuccess(await manager.UpdateAsync(user));
            user.PhoneNumber = "+33123456789";
            IdentityResultAssert.IsSuccess(await manager.UpdateAsync(user));
        }

        protected override void AddUserStore(IServiceCollection services, object context = null)
        {
            services
                .AddLogging(configure => configure.AddProvider(new TestLoggerProvider(_testOutputHelper)))
                .AddIdentity<TestUser, TestRole>()
                .AddRavenDbStores(p => _fixture.Store);
        }

        protected override void AddRoleStore(IServiceCollection services, object context = null)
        {
            services
                .AddLogging(configure => configure.AddProvider(new TestLoggerProvider(_testOutputHelper)))
                .AddIdentity<TestUser, TestRole>()
                .AddRavenDbStores(p => _fixture.Store);
        }

        protected override object CreateTestContext()
        {
            return null;
        }

        protected override TestUser CreateTestUser(string namePrefix = "", string email = "", string phoneNumber = "",
            bool lockoutEnabled = false, DateTimeOffset? lockoutEnd = default(DateTimeOffset?), bool useNamePrefixAsUserName = false)
        {
            return new TestUser
            {
                UserName = useNamePrefixAsUserName ? namePrefix : string.Format("{0}{1}", namePrefix, Guid.NewGuid()),
                Email = email,
                PhoneNumber = phoneNumber,
                LockoutEnabled = lockoutEnabled,
                LockoutEnd = lockoutEnd
            };
        }

        protected override TestRole CreateTestRole(string roleNamePrefix = "", bool useRoleNamePrefixAsRoleName = false)
        {
            var roleName = useRoleNamePrefixAsRoleName ? roleNamePrefix : string.Format("{0}{1}", roleNamePrefix, Guid.NewGuid());
            return new TestRole(roleName);
        }

        protected override void SetUserPasswordHash(TestUser user, string hashedPassword)
        {
            user.PasswordHash = hashedPassword;
        }

        protected override Expression<Func<TestUser, bool>> UserNameEqualsPredicate(string userName) => u => u.UserName == userName;

        protected override Expression<Func<TestRole, bool>> RoleNameEqualsPredicate(string roleName) => r => r.Name == roleName;

        protected override Expression<Func<TestRole, bool>> RoleNameStartsWithPredicate(string roleName) => r => r.Name.StartsWith(roleName);

        protected override Expression<Func<TestUser, bool>> UserNameStartsWithPredicate(string userName) => u => u.UserName.StartsWith(userName);
    }
}
