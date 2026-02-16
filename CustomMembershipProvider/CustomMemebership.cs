using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using System.Linq;
using System.Data.SqlClient;
using System.Text;
using System.Security.Cryptography;
using System.Web.Configuration;
using System.Web.Security;
using PocketDCR.CustomMembershipProvider;
using DatabaseLayer.SQL;
using System.Web.Security;


namespace PocketDCR.CustomMembershipProvider
{
    public class CustomMemebership : MembershipProvider
    {
        #region Class Variables

        private int newPasswordLength = 8;
        private string connectionString;
        private string applicationName;
        private bool enablePasswordReset;
        private bool enablePasswordRetrieval;
        private bool requiresQuestionAndAnswer;
        private bool requiresUniqueEmail;
        private int maxInvalidPasswordAttempts;
        private int passwordAttemptWindow;
        private MembershipPasswordFormat passwordFormat;
        private int minRequiredNonAlphanumericCharacters;
        private int minRequiredPasswordLength;
        private string passwordStrengthRegularExpression;
        
        private MachineKeySection machineKey; //Used when determining encryption key values.

        #endregion

        #region Enums

        private enum FailureType
        {
            Password = 1,
            PasswordAnswer = 2
        }

        #endregion

        #region Properties

        public override string ApplicationName
        {
            get
            {
                return applicationName;
            }
            set
            {
                applicationName = value;
            }
        }

        public override bool EnablePasswordReset
        {
            get
            {
                return enablePasswordReset;
            }
        }

        public override bool EnablePasswordRetrieval
        {
            get
            {
                return enablePasswordRetrieval;
            }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get
            {
                return requiresQuestionAndAnswer;
            }
        }

        public override bool RequiresUniqueEmail
        {
            get
            {
                return requiresUniqueEmail;
            }
        }

        public override int MaxInvalidPasswordAttempts
        {
            get
            {
                return maxInvalidPasswordAttempts;
            }
        }

        public override int PasswordAttemptWindow
        {
            get
            {
                return passwordAttemptWindow;
            }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get
            {
                return passwordFormat;
            }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get
            {
                return minRequiredNonAlphanumericCharacters;
            }
        }

        public override int MinRequiredPasswordLength
        {
            get
            {
                return minRequiredPasswordLength;
            }
        }

        public override string PasswordStrengthRegularExpression
        {
            get
            {
                return passwordStrengthRegularExpression;
            }
        }

        #endregion

        #region Initialization

        public override void Initialize(string name, NameValueCollection config)
        {
            Console.Out.WriteLine("Initilize");

            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            if (name == null || name.Length == 0)
            {
                name = "CustomMemebershipProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Custom membership provider for PocketDCR");
            }

            //Initialize the abstract base class.
            Console.Out.WriteLine("Init 2");
            base.Initialize(name, config);

            applicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            maxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            passwordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));
            minRequiredNonAlphanumericCharacters = Convert.ToInt32(GetConfigValue(config["minRequiredAlphaNumericCharacters"], "1"));
            minRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));
            passwordStrengthRegularExpression = Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], String.Empty));
            enablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "true"));
            enablePasswordRetrieval = Convert.ToBoolean(GetConfigValue(config["enablePasswordRetrieval"], "true"));
            requiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "false"));
            requiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "true"));

            Console.Out.WriteLine("config[0] = {0}", config[0]);
            
            string temp_format = config["passwordFormat"];
            
            if (temp_format == null)
            {
                temp_format = "Clear";
            }

            switch (temp_format)
            {
                case "Hashed":
                    passwordFormat = MembershipPasswordFormat.Hashed;
                    break;

                case "Encrypted":
                    passwordFormat = MembershipPasswordFormat.Encrypted;
                    break;

                case "Clear":
                    passwordFormat = MembershipPasswordFormat.Clear;
                    break;

                default:
                    throw new ProviderException("Password format not supported.");
            }

            ConnectionStringSettings ConnectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

            if ((ConnectionStringSettings == null) || (ConnectionStringSettings.ConnectionString.Trim() == String.Empty))
            {
                throw new ProviderException("Connection string cannot be blank.");
            }

            connectionString = ConnectionStringSettings.ConnectionString;

            //Get encryption and decryption key information from the configuration.
            System.Configuration.Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;

            if (machineKey.ValidationKey.Contains("AutoGenerate"))
            {
                if (PasswordFormat != MembershipPasswordFormat.Clear)
                {
                    throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
                }
            }
        }

        private string GetConfigValue(string configValue, string defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
            {
                return defaultValue;
            }

            return configValue;
        }

        #endregion

        #region Implemented Abstract Methods from MembershipProvider

        /// <summary>
        /// Change the user password.
        /// </summary>
        /// <param name="username">UserName</param>
        /// <param name="oldPwd">Old password.</param>
        /// <param name="newPwd">New password.</param>
        /// <returns>T/F if password was changed.</returns>
        /// 
        
        public override bool ChangePassword(string username, string oldPwd, string newPwd) 
        {
            bool returnValue = false;
            
            try
            {
                if (!ValidateUser(username, oldPwd))
                {
                    return false;
                }

                ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPwd, true);

                OnValidatingPassword(args);

                if (args.Cancel)
                {
                    if (args.FailureInformation != null)
                    {
                        throw args.FailureInformation;
                    }
                    else
                    {
                        throw new Exception("Change password canceled due to new password validation failure.");
                    }
                }


                DatabaseDataContext db = new DatabaseDataContext(connectionString);

                // Check For Old Password If Used Before In Some Month Or Not
                var checkCred = db.sp_ValidatePreCredentials(username, EncodePassword(newPwd)).FirstOrDefault();

                
                if(checkCred.Result.ToString() == "1"){
                    throw new Exception("Please Use The Password Which You Haven't Used In Last 6 Months.");
                }

                //var rawQuery = db.ExecuteCommand("sp_ValidatePreCredentials '" + username + "', '" + EncodePassword(newPwd) + "'");
                ////new SqlParameter("@UserName", username),
                ////new SqlParameter("@Hash", EncodePassword(newPwd)));

                //var abc = db.ExecuteCommand("sp_ValidatePreCredentials '" + username + "', '" + EncodePassword(newPwd) + "'");
                //                    //new SqlParameter("@UserName", username),
                //                    //new SqlParameter("@Hash", EncodePassword(newPwd)));


                
                
                var changePassword = db.sp_EmployeeChangePassword(username, EncodePassword(newPwd), DateTime.Now);

                if (changePassword == 0)
                {
                    returnValue = true;
                }
                //changePassword.ToString()
            }
            catch (Exception)
            {
                throw;          
            }

            return   returnValue;

        }

        /// <summary>
        /// Change the question and answer for a password validation.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="password">Password.</param>
        /// <param name="newPwdQuestion">New question text.</param>
        /// <param name="newPwdAnswer">New answer text.</param>
        /// <returns></returns>
        /// <remarks></remarks>
        public override bool ChangePasswordQuestionAndAnswer(
        string username,
          string password,
         string newPwdQuestion,
          string newPwdAnswer)
        {

            if (!ValidateUser(username, password))
            {
                return false;
            }

            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("User_ChangePasswordQuestionAnswer", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@returnValue", SqlDbType.Int, 0).Direction = ParameterDirection.ReturnValue;
            sqlCommand.Parameters.Add("@question", SqlDbType.NVarChar, 255).Value = newPwdQuestion;
            sqlCommand.Parameters.Add("@answer", SqlDbType.NVarChar, 255).Value = EncodePassword(newPwdAnswer);
            sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = username; ;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            try
            {
                sqlConnection.Open();
                sqlCommand.ExecuteNonQuery();
                if ((int)sqlCommand.Parameters["@returnValue"].Value != 0)
                {
                    return false;
                }
            }
            catch (SqlException)
            {
                //Add exception handling here.
                return false;
            }
            finally
            {
                sqlConnection.Close();
            }

            return true;

        }
        /// <summary>
        /// Create a new user.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="password">Password.</param>
        /// <param name="email">Email address.</param>
        /// <param name="passwordQuestion">Security quesiton for password.</param>
        /// <param name="passwordAnswer">Security quesiton answer for password.</param>
        /// <param name="isApproved"></param>
        /// <param name="userID">User ID</param>
        /// <param name="status"></param>
        /// <returns>MembershipUser</returns>

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {

            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, password, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if ((RequiresUniqueEmail && (GetUserNameByEmail(email) != String.Empty)))
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            MembershipUser membershipUser = GetUser(username, false);

            if (membershipUser == null)
            {
                System.DateTime createDate = DateTime.Now;

                SqlConnection sqlConnection = new SqlConnection(connectionString);
                SqlCommand sqlCommand = new SqlCommand("User_Ins", sqlConnection);

                sqlCommand.CommandType = CommandType.StoredProcedure;
                sqlCommand.Parameters.Add("@returnValue", SqlDbType.Int, 0).Direction = ParameterDirection.ReturnValue;
                sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = username; ;
                sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;
                sqlCommand.Parameters.Add("@password", SqlDbType.NVarChar, 255).Value = EncodePassword(password);
                sqlCommand.Parameters.Add("@email", SqlDbType.NVarChar, 128).Value = email;
                sqlCommand.Parameters.Add("@passwordQuestion", SqlDbType.NVarChar, 255).Value = passwordQuestion;
                sqlCommand.Parameters.Add("@passwordAnswer", SqlDbType.NVarChar, 255).Value = EncodePassword(passwordAnswer);
                sqlCommand.Parameters.Add("@isApproved", SqlDbType.Bit).Value = isApproved;
                sqlCommand.Parameters.Add("@comment", SqlDbType.NVarChar, 255).Value = String.Empty;

                try
                {
                    sqlConnection.Open();

                    sqlCommand.ExecuteNonQuery();
                    if ((int)sqlCommand.Parameters["@returnValue"].Value == 0)
                    {

                        status = MembershipCreateStatus.Success;
                    }
                    else
                    {
                        status = MembershipCreateStatus.UserRejected;
                    }
                }
                catch (SqlException)
                {
                    //Add exception handling here.

                    status = MembershipCreateStatus.ProviderError;
                }
                finally
                {
                    sqlConnection.Close();
                }

                return GetUser(username, false);
            }
            else
            {
                status = MembershipCreateStatus.DuplicateUserName;
            }

            return null;
        }
        /// <summary>
        /// Delete a user.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="deleteAllRelatedData">Whether to delete all related data.</param>
        /// <returns>T/F if the user was deleted.</returns>
        public override bool DeleteUser(
         string username,
         bool deleteAllRelatedData
        )
        {

            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("User_Del", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@returnValue", SqlDbType.Int, 0).Direction = ParameterDirection.ReturnValue;
            sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = username; ;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            try
            {
                sqlConnection.Open();
                sqlCommand.ExecuteNonQuery();
                if ((int)sqlCommand.Parameters["@returnValue"].Value == 0)
                {
                    if (deleteAllRelatedData)
                    {
                        //Process commands to delete all data for the user in the database.
                    }
                }
                else
                {
                    return false;
                }
            }
            catch (SqlException)
            {
                //Add exception handling here.
            }
            finally
            {
                sqlConnection.Close();
            }

            return true;

        }
        /// <summary>
        /// Get a collection of users.
        /// </summary>
        /// <param name="pageIndex">Page index.</param>
        /// <param name="pageSize">Page size.</param>
        /// <param name="totalRecords">Total # of records to retrieve.</param>
        /// <returns>Collection of MembershipUser objects.</returns>

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {

            MembershipUserCollection users = new MembershipUserCollection();
            DatabaseDataContext db = new DatabaseDataContext(connectionString);


            var employeesWithMembership = db.sp_EmployeesSelectWithMembership();
            totalRecords = 0;

            foreach (var employeeWithMembership in employeesWithMembership)
            {



                //if (employeeWithMembership.DistributorID != null)
                //{
                //    customerId = (int)systemUserView.DistributorID;
                //}

                //if (systemUserView.SMSCustomerID != null)
                //{
                //    distributrId = (int)systemUserView.SMSCustomerID;
                //}
                //MembershipUser membershipUser =  new MembershipUser(
                //    this.Name,
                //    systemUserView.UserLoginID,
                //    systemUserView.UserLoginID,
                //    systemUserView.UserEmail, "NA",
                //    "NA", systemUserView.IsActive, systemUserView.IsActive,
                //    systemUserView.TimeStamp,
                //    DateTime.Now, DateTime.Now,
                //    systemUserView.TimeStamp,
                //    systemUserView.TimeStamp);

                SystemUser membershipUser = new SystemUser(
                    this.Name,

                    employeeWithMembership.LoginId,
                    employeeWithMembership.LoginId,
                    employeeWithMembership.Email,
                    employeeWithMembership.PasswordQuestion, employeeWithMembership.Comment,
                     employeeWithMembership.IsApproved, employeeWithMembership.IsLockedOut,
                    employeeWithMembership.CreationDate,
                    employeeWithMembership.LastLoginDate, employeeWithMembership.LastLoginDate,
                    employeeWithMembership.LastPasswordChangedDate,
                    employeeWithMembership.LastLockoutDate,
                    employeeWithMembership.EmployeeId);

                users.Add(membershipUser);
                
                totalRecords++;
            }

             
            return users;

        }
        /// <summary>
        /// Gets the number of users currently on-line.
        /// </summary>
        /// <returns>  /// # of users on-line.</returns>
        public override int GetNumberOfUsersOnline()
        {

            TimeSpan onlineSpan = new TimeSpan(0, System.Web.Security.Membership.UserIsOnlineTimeWindow, 0);
            DateTime compareTime = DateTime.Now.Subtract(onlineSpan);

            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("Users_NumberOnline", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;
            sqlCommand.Parameters.Add("@compareDate", SqlDbType.DateTime).Value = compareTime;

            int numOnline = 0;

            try
            {
                sqlConnection.Open();

                numOnline = Convert.ToInt32(sqlCommand.ExecuteScalar());
            }
            catch (SqlException)
            {
                //Add exception handling here.
            }
            finally
            {
                sqlConnection.Close();
            }

            return numOnline;

        }
        /// <summary>
        /// Get the password for a user.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="answer">Answer to security question.</param>
        /// <returns>Password for the user.</returns>
        public override string GetPassword(
         string username,
         string answer
        )
        {

            if (!EnablePasswordRetrieval)
            {
                throw new ProviderException("Password Retrieval Not Enabled.");
            }

            if (PasswordFormat == MembershipPasswordFormat.Hashed)
            {
                throw new ProviderException("Cannot retrieve Hashed passwords.");
            }

            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("User_GetPassword", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = username;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            string password = String.Empty;
            string passwordAnswer = String.Empty;
            SqlDataReader sqlDataReader = null;

            try
            {
                sqlConnection.Open();

                sqlDataReader = sqlCommand.ExecuteReader(CommandBehavior.SingleRow & CommandBehavior.CloseConnection);

                if (sqlDataReader.HasRows)
                {
                    sqlDataReader.Read();

                    if (sqlDataReader.GetBoolean(2))
                    {
                        throw new MembershipPasswordException("The supplied user is locked out.");
                    }

                    password = sqlDataReader.GetString(0);
                    passwordAnswer = sqlDataReader.GetString(1);
                }
                else
                {
                    throw new MembershipPasswordException("The supplied user name is not found.");
                }
            }
            catch (SqlException)
            {
                //Add exception handling here.
            }
            finally
            {
                if (sqlDataReader != null) { sqlDataReader.Close(); }
            }

            if (RequiresQuestionAndAnswer && !CheckPassword(answer, passwordAnswer))
            {
                UpdateFailureCount(username, FailureType.PasswordAnswer);

                throw new MembershipPasswordException("Incorrect password answer.");
            }

            if (PasswordFormat == MembershipPasswordFormat.Encrypted)
            {
                password = UnEncodePassword(password);
            }

            return password;
        }

        public override MembershipUser GetUser(
        string username,
         bool userIsOnline
        )
        {

            SystemUser membershipUser = null;

            DatabaseDataContext db = new DatabaseDataContext(connectionString);

            var employeesSelectWithMembership =
                db.sp_EmployeesSelectWithMembership01(username, null).ToList();

            foreach (var employee in employeesSelectWithMembership)
            {
                membershipUser = new SystemUser(
                    this.Name,
                    employee.LoginId,
                    employee.EmployeeId,
                    employee.Email,
                    employee.PasswordQuestion,
                    employee.Comment,
                    employee.IsApproved,
                    employee.IsLockedOut,
                    employee.CreationDate,
                    employee.LastLoginDate,
                    employee.LastLoginDate,
                    employee.LastPasswordChangedDate,
                    employee.LastLockoutDate,
                    employee.EmployeeId
                    );

            }

            return membershipUser;
        }

        /// <summary>
        /// Get a user based upon provider key and if they are on-line.
        /// </summary>
        /// <param name="userID">Provider key.</param>
        /// <param name="userIsOnline">T/F whether the user is on-line.</param>
        /// <returns></returns>
        public override MembershipUser GetUser(
         object userID,
         bool userIsOnline
        )
        {

            SystemUser membershipUser = null;

            DatabaseDataContext db = new DatabaseDataContext(connectionString);

            var employeesSelectWithMembership =
                db.sp_EmployeesSelectWithMembership01(userID.ToString(), null);

            foreach (var employee in employeesSelectWithMembership)
            {
                membershipUser = new SystemUser(
                    this.Name,
                    employee.LoginId,
                    employee.EmployeeId,
                    employee.Email,
                    employee.PasswordQuestion,
                    employee.Comment,
                    employee.IsApproved,
                    employee.IsLockedOut,
                    employee.CreationDate,
                    employee.LastLoginDate,
                    employee.LastLoginDate,
                    employee.LastPasswordChangedDate,
                    employee.LastLockoutDate,
                    employee.EmployeeId);

            }

            //var smsSystemUserViews = db.sp_SMSSystemUsersSelect01(userID.ToString(), null, true,null);
            //foreach (var smsSystemUserView in smsSystemUserViews)
            //{
            //    long customerId = 0;
            //    int distributrId = 0;
            //    if (smsSystemUserView.SMSCustomerID != null)
            //    {
            //        customerId = (long)smsSystemUserView.SMSCustomerID;
            //    }
            //    if (smsSystemUserView.DistributorID != null)
            //    {
            //        distributrId = (int)smsSystemUserView.DistributorID;
            //    }
            //    membershipUser = new SystemUser(
            //        this.Name,
            //        smsSystemUserView.UserName,
            //        smsSystemUserView.UserLoginID,
            //        smsSystemUserView.UserEmail, "NA",
            //        "NA", smsSystemUserView.IsActive, smsSystemUserView.IsActive,
            //        smsSystemUserView.TimeStamp,
            //        DateTime.Now, DateTime.Now,
            //        smsSystemUserView.TimeStamp,
            //        smsSystemUserView.TimeStamp,
            //        distributrId, customerId,
            //        smsSystemUserView.SystemUserID);  
            //}



            return membershipUser;

        }

        /// <summary>
        /// Unlock a user.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <returns>T/F if unlocked.</returns>
        public override bool UnlockUser(
         string username
        )
        {

            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("User_Unlock", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@returnValue", SqlDbType.Int, 0).Direction = ParameterDirection.ReturnValue;
            sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = username;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            try
            {
                sqlConnection.Open();

                sqlCommand.ExecuteNonQuery();
                if ((int)sqlCommand.Parameters["@returnValue"].Value == 0)
                {
                    return false;
                }
            }
            catch (SqlException)
            {
                //Add exception handling here.
                return false;
            }
            finally
            {
                sqlConnection.Close();
            }

            return true;

        }


        public override string GetUserNameByEmail(string email)
        {

            string username = String.Empty;
            DatabaseDataContext db = new DatabaseDataContext(connectionString);
            List<EmployeesSelectWithMembership> employeesSelectWithMemberships =
                db.sp_EmployeesSelectWithMembership01(null, email).ToList();

            username = employeesSelectWithMemberships[0].LoginId;
         
            return username;

        }
        /// <summary>
        /// Reset the user password.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="answer">Answer to security question.</param>
        /// <returns></returns>
        /// <remarks></remarks>
        public override string ResetPassword(
         string username,
         string answer
        )
        {

            if (!EnablePasswordReset)
            {
                throw new NotSupportedException("Password Reset is not enabled.");
            }

            //if ((answer == null) && (RequiresQuestionAndAnswer))
            //{
            //    UpdateFailureCount(username, FailureType.PasswordAnswer);

            //    throw new ProviderException("Password answer required for password Reset.");
            //}

            string newPassword =
              System.Web.Security.Membership.GeneratePassword(
              newPasswordLength,
              MinRequiredNonAlphanumericCharacters
              );

            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                if (args.FailureInformation != null)
                {
                    throw args.FailureInformation;
                }
                else
                {
                    throw new MembershipPasswordException("Reset password canceled due to password validation failure.");
                }
            }

            DatabaseDataContext db = new DatabaseDataContext(connectionString);


            List<EmployeesSelectWithMembership> employeesSelectWithMemberships =
                db.sp_EmployeesSelectWithMembership01(username, null).ToList();


            if (employeesSelectWithMemberships != null)
            {
                if (employeesSelectWithMemberships[0].IsApproved == false)
                {
                    throw new MembershipPasswordException("The supplied user is not valid.");
                }
                else
                {
                    //EncodePassword(username)
                   List<EmployeeMembership> employeeMembership =
                        db.sp_EmployeeMembershipUpdatePassword(employeesSelectWithMemberships[0].EmployeeId,
                                                               EncodePassword(newPassword)).ToList();

                   if (employeeMembership == null)
                    {
                        throw new MembershipPasswordException("Unknown error occoured. Please try later.");
                    }
                }

            }
            else
            {
                throw new MembershipPasswordException("The supplied user is not valid.");
            }


            return newPassword;
        }

        /// <summary>
        /// Reset the user password.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="answer">Answer to security question.</param>
        /// <returns></returns>
        /// <remarks></remarks>
        public string ResetPassword(
         string username,
         string email,bool isonline
        )
        {

            if (!EnablePasswordReset)
            {
                throw new NotSupportedException("Password Reset is not enabled.");
            }

            //if ((answer == null) && (RequiresQuestionAndAnswer))
            //{
            //    UpdateFailureCount(username, FailureType.PasswordAnswer);

            //    throw new ProviderException("Password answer required for password Reset.");
            //}

            string newPassword =
              System.Web.Security.Membership.GeneratePassword(
              newPasswordLength,
              MinRequiredNonAlphanumericCharacters
              );

            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                if (args.FailureInformation != null)
                {
                    throw args.FailureInformation;
                }
                else
                {
                    throw new MembershipPasswordException("Provided information is incorrect.");
                }
            }


            return newPassword;
        }

        /// <summary>
        /// Update the user information.
        /// </summary>
        /// <param name="_membershipUser">MembershipUser object containing data.</param>
        public override void UpdateUser(MembershipUser membershipUser)
        {

            //SqlConnection sqlConnection = new SqlConnection(connectionString);
            //SqlCommand sqlCommand = new SqlCommand("User_Upd", sqlConnection);

            //sqlCommand.CommandType = CommandType.StoredProcedure;
            //sqlCommand.Parameters.Add("@email", SqlDbType.NVarChar, 128).Value = membershipUser.Email;
            //sqlCommand.Parameters.Add("@comment", SqlDbType.NVarChar, 255).Value = membershipUser.Comment;
            //sqlCommand.Parameters.Add("@isApproved", SqlDbType.Bit).Value = membershipUser.IsApproved;
            //sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = membershipUser.UserName;
            //sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            //try
            //{
            //    sqlConnection.Open();
            //    sqlCommand.ExecuteNonQuery();
            //}
            //catch (SqlException e)
            //{
            //    //Add exception handling here.
            //}
            //finally
            //{
            //    sqlConnection.Close();
            //}
        }

        /// <summary>
        /// Validate the user based upon username and password.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="password">Password.</param>
        /// <returns>T/F if the user is valid.</returns>
        public override bool ValidateUser(
         string username,
         string password
        )
        {
            bool isValid = false;
            DatabaseDataContext db = new DatabaseDataContext(connectionString);

            string encodedpassword = EncodePassword(password);


            var emploees = db.sp_EmployeeValidateUserPassword(username, encodedpassword, true); 
            

            foreach (var emploee in emploees)
            {

                    if (emploee.IsActive)
                    {

                        isValid = true;

                        db.sp_EmployeeMembershipUpdateLoginDate(emploee.EmployeeId, DateTime.Now);

                    }
                    else
                    {
                        isValid = false;
                    }
  
            }
            
            return isValid;
        }

        /// <summary>
        /// Find all users matching a search string.
        /// </summary>
        /// <param name="usernameToMatch">Search string of user name to match.</param>
        /// <param name="pageIndex"></param>
        /// <param name="pageSize"></param>
        /// <param name="totalRecords">Total records found.</param>
        /// <returns>Collection of MembershipUser objects.</returns>

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("Users_Sel_ByUserName", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@username", SqlDbType.NVarChar, 255).Value = usernameToMatch;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            MembershipUserCollection membershipUsers = new MembershipUserCollection();
            SqlDataReader sqlDataReader = null;
            int counter = 0;

            try
            {
                sqlConnection.Open();
                sqlDataReader = sqlCommand.ExecuteReader(CommandBehavior.CloseConnection);

                int startIndex = pageSize * pageIndex;
                int endIndex = startIndex + pageSize - 1;

                while (sqlDataReader.Read())
                {
                    if (counter >= startIndex)
                    {
                        MembershipUser membershipUser = GetUserFromReader(sqlDataReader);
                        membershipUsers.Add(membershipUser);
                    }

                    if (counter >= endIndex) { sqlCommand.Cancel(); }

                    counter += 1;
                }
            }
            catch (SqlException)
            {
                //Add exception handling here.
            }
            finally
            {
                if (sqlDataReader != null) { sqlDataReader.Close(); }
            }

            totalRecords = counter;

            return membershipUsers;
        }

        /// <summary>
        /// Find all users matching a search string of their email.
        /// </summary>
        /// <param name="emailToMatch">Search string of email to match.</param>
        /// <param name="pageIndex"></param>
        /// <param name="pageSize"></param>
        /// <param name="totalRecords">Total records found.</param>
        /// <returns>Collection of MembershipUser objects.</returns>

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {

            DatabaseDataContext db = new DatabaseDataContext(connectionString);




            //SqlConnection sqlConnection = new SqlConnection(connectionString);
            //SqlCommand sqlCommand = new SqlCommand("Users_Sel_ByUserName", sqlConnection);

            //sqlCommand.CommandType = CommandType.StoredProcedure;
            //sqlCommand.Parameters.Add("@email", SqlDbType.NVarChar, 255).Value = emailToMatch;
            //sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            MembershipUserCollection membershipUsers = new MembershipUserCollection();
            int counter = 0;

            try
            {
                //sqlConnection.Open();
                //sqlDataReader = sqlCommand.ExecuteReader(CommandBehavior.CloseConnection);

                //int startIndex = pageSize * pageIndex;
                //int endIndex = startIndex + pageSize - 1;

                List<EmployeesSelectWithMembership> employeeWithMemberShip =
                    db.sp_EmployeesSelectWithMembership01(null, emailToMatch).ToList();

                foreach (var employee in employeeWithMemberShip)
                {
                    SystemUser membershipUser = GetUserFromLinq(employee);
                    membershipUsers.Add(membershipUser);
                    counter += 1;
                }

                //while (sqlDataReader.Read())
                //{
                //    if (counter >= startIndex)
                //    {
                //        MembershipUser membershipUser = GetUserFromReader(sqlDataReader);
                //        membershipUsers.Add(membershipUser);
                //    }

                //    if (counter >= endIndex) { sqlCommand.Cancel(); }

                //    counter += 1;
                //}
            }
            catch (SqlException)
            {
                //Add exception handling here.
            }
            finally
            {
                
            }

            totalRecords = counter;

            return membershipUsers;
        }

        #endregion

        #region "Utility Functions"
        /// <summary>
        /// Create a MembershipUser object from a data reader.
        /// </summary>
        /// <param name="sqlDataReader">Data reader.</param>
        /// <returns>MembershipUser object.</returns>
        private MembershipUser GetUserFromReader(
      SqlDataReader sqlDataReader
        )
        {

            object userID = sqlDataReader.GetValue(0);
            string username = sqlDataReader.GetString(1);
            string email = sqlDataReader.GetString(2);

            string passwordQuestion = String.Empty;
            if (sqlDataReader.GetValue(3) != DBNull.Value)
            {
                passwordQuestion = sqlDataReader.GetString(3);
            }

            string comment = String.Empty;
            if (sqlDataReader.GetValue(4) != DBNull.Value)
            {
                comment = sqlDataReader.GetString(4);
            }

            bool isApproved = sqlDataReader.GetBoolean(5);
            bool isLockedOut = sqlDataReader.GetBoolean(6);
            DateTime creationDate = sqlDataReader.GetDateTime(7);

            DateTime lastLoginDate = new DateTime();
            if (sqlDataReader.GetValue(8) != DBNull.Value)
            {
                lastLoginDate = sqlDataReader.GetDateTime(8);
            }

            DateTime lastActivityDate = sqlDataReader.GetDateTime(9);
            DateTime lastPasswordChangedDate = sqlDataReader.GetDateTime(10);

            DateTime lastLockedOutDate = new DateTime();
            if (sqlDataReader.GetValue(11) != DBNull.Value)
            {
                lastLockedOutDate = sqlDataReader.GetDateTime(11);
            }

            MembershipUser membershipUser = new MembershipUser(
              this.Name,
             username,
             userID,
             email,
             passwordQuestion,
             comment,
             isApproved,
             isLockedOut,
             creationDate,
             lastLoginDate,
             lastActivityDate,
             lastPasswordChangedDate,
             lastLockedOutDate
              );

            return membershipUser;

        }


        /// <summary>
        /// Create a MembershipUser object from a data reader.
        /// </summary>
        /// <param name="sqlDataReader">Data reader.</param>
        /// <returns>MembershipUser object.</returns>
        private SystemUser GetUserFromLinq(
        EmployeesSelectWithMembership employee
        )
        {

            long employeeId = employee.EmployeeId;
            object userID = employee.LoginId;
            string username = employee.LoginId;
            string email = employee.Email;

            string passwordQuestion = String.Empty;

            //if (sqlDataReader.GetValue(3) != DBNull.Value)
            //{
            passwordQuestion = employee.PasswordQuestion;
            //}

            string comment = String.Empty;
            //if (sqlDataReader.GetValue(4) != DBNull.Value)
            //{
            comment = employee.Comment;
            //}

            bool isApproved = employee.IsApproved;
            bool isLockedOut = employee.IsLockedOut;
            DateTime creationDate = employee.CreationDate;

            DateTime lastLoginDate = new DateTime();
            //if (sqlDataReader.GetValue(8) != DBNull.Value)
            //{
            lastLoginDate = employee.LastLoginDate;
            //}

            DateTime lastActivityDate = employee.LastLoginDate;
            DateTime lastPasswordChangedDate = employee.LastPasswordChangedDate;

            DateTime lastLockedOutDate = new DateTime();
            //if (sqlDataReader.GetValue(11) != DBNull.Value)
            //{
            lastLockedOutDate = employee.LastLockoutDate;
            //}

            SystemUser membershipUser = new  SystemUser(
              this.Name,
             username,
             employeeId,
             email,
             passwordQuestion,
             comment,
             isApproved,
             isLockedOut,
             creationDate,
             lastLoginDate,
             lastActivityDate,
             lastPasswordChangedDate,
             lastLockedOutDate,
             employeeId
             );

            return membershipUser;

        }


        /// <summary>
        /// Converts a hexadecimal string to a byte array. Used to convert encryption key values from the configuration
        /// </summary>
        /// <param name="hexString"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        private byte[] HexToByte(string hexString)
        {
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }

        /// <summary>
        /// Update password and answer failure information.
        /// </summary>
        /// <param name="username">User name.</param>
        /// <param name="failureType">Type of failure</param>
        /// <remarks></remarks>
        private void UpdateFailureCount(string username, FailureType failureType)
        {

            SqlConnection sqlConnection = new SqlConnection(connectionString);
            SqlCommand sqlCommand = new SqlCommand("Users_Sel_ByUserName", sqlConnection);

            sqlCommand.CommandType = CommandType.StoredProcedure;
            sqlCommand.Parameters.Add("@failureType", SqlDbType.Int, 0).Value = failureType;
            sqlCommand.Parameters.Add("@passwordAttempWindow", SqlDbType.DateTime, 0).Value = passwordAttemptWindow;
            sqlCommand.Parameters.Add("@maxInvalidPasswordAttempts", SqlDbType.Int, 0).Value = maxInvalidPasswordAttempts;
            sqlCommand.Parameters.Add("@userName", SqlDbType.NVarChar, 255).Value = username;
            sqlCommand.Parameters.Add("@applicationName", SqlDbType.NVarChar, 255).Value = applicationName;

            try
            {
                sqlConnection.Open();
                sqlCommand.ExecuteNonQuery();
            }
            catch (Exception)
            {
                //Add exception handling here.
            }

        }
        public string EncryptedPassword(string Password)
        {

            passwordFormat = MembershipPasswordFormat.Hashed;
            System.Configuration.Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            machineKey = cfg.GetSection("system.web/machineKey") as MachineKeySection;
            return EncodePassword(Password);
        }

        /// <summary>
        /// Check the password format based upon the MembershipPasswordFormat.
        /// </summary>
        /// <param name="password">Password</param>
        /// <param name="dbpassword"></param>
        /// <returns></returns>
        /// <remarks></remarks>
        private bool CheckPassword(string password, string dbpassword)
        {
            string pass1 = password;
            string pass2 = dbpassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Encrypted:
                    pass2 = UnEncodePassword(dbpassword);
                    break;
                case MembershipPasswordFormat.Hashed:
                    pass1 = EncodePassword(password);
                    break;
                default:
                    break;
            }

            if (pass1 == pass2)
            {
                return true;
            }

            return false;
        }

        /// <summary>
        /// Encode password.
        /// </summary>
        /// <param name="password">Password.</param>
        /// <returns>Encoded password.</returns>
        private string EncodePassword(string password)
        {
            string encodedPassword = password;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    encodedPassword =
                      Convert.ToBase64String(EncryptPassword(Encoding.Unicode.GetBytes(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    HMACSHA1 hash = new HMACSHA1();
                    hash.Key = HexToByte(machineKey.ValidationKey);
                    encodedPassword =
                      Convert.ToBase64String(hash.ComputeHash(Encoding.Unicode.GetBytes(password)));
                    break;
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return encodedPassword;
        }

        /// <summary>
        /// UnEncode password.
        /// </summary>
        /// <param name="encodedPassword">Password.</param>
        /// <returns>Unencoded password.</returns>
        private string UnEncodePassword(string encodedPassword)
        {
            string password = encodedPassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    password =
                      Encoding.Unicode.GetString(DecryptPassword(Convert.FromBase64String(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Cannot unencode a hashed password.");
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return password;
        }

        #endregion
    }
}