using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DatabaseLayer.SQL
{
    public partial class DatabaseDataContext : System.Data.Linq.DataContext
    {
        public DatabaseDataContext()
            : base(System.Configuration.ConfigurationManager.ConnectionStrings["PocketDCRConnectionString"].ConnectionString)
        {
            OnCreated();
        }
    }
}
