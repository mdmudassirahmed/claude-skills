using System;
using System.Collections.Generic;
using System.Linq;

namespace Shop.Billing
{
    public class Invoice
    {
        public DateTime? PaidOn { get; set; }

        public string Describe(Invoice other)
        {
            int? days = null;
            var paid = other.PaidOn.Value.ToString("d");
            var d = days.Value + 1;
            Nullable<int> n = null;
            if (n != null) { return n.Value.ToString(); }
            var lazy = new Lazy<int>(() => 1);
            var list = new List<int>();
            var one = list.Single(x => x > 1);
            return paid + d + lazy.Value + one;
        }
    }
}
