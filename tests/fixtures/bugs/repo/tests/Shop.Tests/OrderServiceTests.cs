using Xunit;

namespace Shop.Tests
{
    public class OrderServiceTests
    {
        [Fact]
        public void Total_WithoutDiscount_DoesNotThrow()
        {
            var order = new Shop.Orders.Order();
            Assert.Equal(0m, order.Discount.Value);
        }

        public async void Helper() { }
    }
}
