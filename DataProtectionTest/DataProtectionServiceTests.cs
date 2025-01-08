using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DataProtectionTest
{
    public class DataProtectionServiceTests
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;
        private readonly string _keyPath;

        public DataProtectionServiceTests()
        {
            // Create a temporary directory for keys
            _keyPath = Path.Combine(Path.GetTempPath(), "DataProtection-Keys-" + Guid.NewGuid().ToString());
            Directory.CreateDirectory(_keyPath);

            // Setup DI container
            var services = new ServiceCollection();

            // Configure data protection
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(_keyPath))
                .SetApplicationName("TestApp");

            var serviceProvider = services.BuildServiceProvider();
            _dataProtectionProvider = serviceProvider.GetRequiredService<IDataProtectionProvider>();
        }
    }
}