namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Configuration options for <see cref="BasicAuthenticationOptions"/>.
    /// </summary>
    public class BasicAuthenticationOptions : AuthenticationSchemeOptions
    {
        private const string DefaultCharSet = "UTF-8";

        /// <summary>
        /// Gets or sets the Realm
        /// </summary>
        public string? Realm { get; set; }

        /// <summary>
        /// Gets or sets the CharSet
        /// </summary>
        public string? CharSet { get; set; } = DefaultCharSet;

        /// <summary>
        /// Gets or sets a value that allows subscribing to Basic authentication events.
        /// </summary>
        public new BasicAuthenticationEvents Events
        {
            get => (BasicAuthenticationEvents)base.Events!;
            set => base.Events = value;
        }

        /// <summary>
        /// Check that the options are valid. Should throw an exception if things are not ok.
        /// </summary>
        public override void Validate()
        {
            base.Validate();

            if (string.IsNullOrWhiteSpace(Realm))
            {
                throw new ArgumentException($"{nameof(Realm)} is required", nameof(Realm));
            }
            if (!string.IsNullOrEmpty(CharSet) && !CharSet.Equals(DefaultCharSet, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException($"Only \"{DefaultCharSet}\" is allowed", nameof(CharSet));
            }
        }

        internal string GetWWWAuthenticate() => string.IsNullOrEmpty(CharSet)
            ? $"{BasicAuthenticationDefaults.AuthenticationScheme} realm=\"{Realm}\""
            : $"{BasicAuthenticationDefaults.AuthenticationScheme} realm=\"{Realm}\", charset=\"{CharSet}\"";
    }
}