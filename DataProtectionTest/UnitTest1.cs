using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using System.Security.Cryptography;

namespace DataProtectionTest
{
    public class Tests
    {
        private IDataProtectionProvider _dataProtectionProvider;
        private string _keyPath;
        [SetUp]
        public void Setup()
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

        [Test]
        public void ProtectUnprotect_SameKeyRing_WorksCorrectly()
        {
            // Arrange
            var protector = _dataProtectionProvider.CreateProtector("TestPurpose");
            var originalData = "sensitive data";

            // Act
            var protectedData = protector.Protect(originalData);
            var unprotectedData = protector.Unprotect(protectedData);

            // Assert
            Assert.That(originalData==unprotectedData);
            //Assert.Pass();
        }
        [Test]
        public void ProtectUnprotect_DifferentKeyRing_ThrowsException()
        {
            // Arrange
            var protector1 = _dataProtectionProvider.CreateProtector("TestPurpose");
            var originalData = "sensitive data";
            var protectedData = protector1.Protect(originalData);

            // Create a new provider with different key ring
            var differentKeyPath = Path.Combine(Path.GetTempPath(), "DataProtection-Keys-" + Guid.NewGuid().ToString());
            Directory.CreateDirectory(differentKeyPath);

            var services = new ServiceCollection();
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(differentKeyPath))
                .SetApplicationName("TestApp");

            var differentProvider = services.BuildServiceProvider()
                .GetRequiredService<IDataProtectionProvider>();
            var protector2 = differentProvider.CreateProtector("TestPurpose");

            // Act & Assert
            Assert.Throws<CryptographicException>(() => protector2.Unprotect(protectedData));
        }
        [Test]
        public void ProtectUnprotect_PersistentKeys_WorksAcrossInstances()
        {
            // Arrange
            var protector1 = _dataProtectionProvider.CreateProtector("TestPurpose");
            var originalData = "sensitive data";
            var protectedData = protector1.Protect(originalData);

            // Create a new provider using the same key ring
            var services = new ServiceCollection();
            services.AddDataProtection()
                .PersistKeysToFileSystem(new DirectoryInfo(_keyPath))
                .SetApplicationName("TestApp");

            var sameKeyProvider = services.BuildServiceProvider()
                .GetRequiredService<IDataProtectionProvider>();
            var protector2 = sameKeyProvider.CreateProtector("TestPurpose");

            // Act
            var unprotectedData = protector2.Unprotect(protectedData);

            // Assert
            Assert.That(originalData == unprotectedData);
        }
    }
}
