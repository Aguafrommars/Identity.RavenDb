﻿// Project: Aguafrommars/Identity.RavenDb
// Copyright (c) 2025 Olivier Lefebvre
using Microsoft.Extensions.Logging;
using System.Diagnostics.CodeAnalysis;
using Xunit.Abstractions;

namespace Aguacongas.Identity.RavenDb.IntegrationTest
{
    [SuppressMessage("Major Code Smell", "S3881:\"IDisposable\" should be implemented correctly", Justification = "<Pending>")]
    internal class TestLoggerProvider : ILoggerProvider
    {
        public ITestOutputHelper TestOutputHelper { get; set; }

        public TestLoggerProvider(ITestOutputHelper testOutputHelper)
        {
            TestOutputHelper = testOutputHelper;
        }

        public TestLoggerProvider()
        { }

        public ILogger CreateLogger(string categoryName)
        {
            return new TestLogger(TestOutputHelper);
        }

        [SuppressMessage("Critical Code Smell", "S1186:Methods should not be empty", Justification = "<Pending>")]
        public void Dispose()
        {

        }
    }
}
