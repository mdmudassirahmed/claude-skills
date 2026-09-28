using System;
using System.Collections.Generic;
using System.Linq;

namespace Shop.Orders
{
    public class Order
    {
        public decimal? Discount { get; set; }
        public int Quantity { get; set; }
        public List<string> Tags { get; set; } = new List<string>();
    }

    public class OrderService
    {
        private readonly Dictionary<string, int> _stock = new Dictionary<string, int>();

        public decimal Total(Order order, decimal price)
        {
            return price * order.Quantity - order.Discount.Value;
        }

        public decimal SafeTotal(Order order, decimal price)
        {
            if (order.Discount.HasValue)
            {
                return price - order.Discount.Value;
            }
            return price;
        }

        public int StockOf(string sku)
        {
            foreach (var pair in _stock)
            {
                if (pair.Key == sku) return pair.Value;
            }
            return 0;
        }

        public string FirstTag(Order order)
        {
            return order.Tags.First();
        }

        public string FirstTagSafe(Order order)
        {
            if (order.Tags.Any())
            {
                return order.Tags.First();
            }
            return order.Tags.FirstOrDefault();
        }

        public async void Refresh()
        {
            await System.Threading.Tasks.Task.Delay(1);
        }

        public async void OnClick(object sender, EventArgs e)
        {
            await System.Threading.Tasks.Task.Delay(1);
        }

        // var sql = "SELECT * FROM Customers WHERE Name = '" + name + "'";
        public string Lookup(SqlConnection conn, string name)
        {
            var sql = "SELECT * FROM Customers WHERE Name = '" + name + "'";
            var sql2 = $"SELECT * FROM Customers WHERE Name = '{name}'";
            var cmd = new SqlCommand("SELECT * FROM Customers WHERE Name = @name", conn);
            return sql + sql2;
        }
    }
}
