namespace Microsoft.AspNetCore.Authentication.Basic
{
    /// <summary>
    /// Basic authentication events
    /// </summary>
    public class BasicAuthenticationEvents
    {
        /// <summary>
        /// Invoked if authentication fails during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public Func<AuthenticationFailedContext, Task> OnAuthenticationFailed { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public Func<MessageReceivedContext, Task> OnMessageReceived { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked after the user-password has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public Func<UserAuthenticatedContext, Task> OnUserAuthenticated { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked if exceptions are thrown during request processing. The exceptions will be re-thrown after this event unless suppressed.
        /// </summary>
        public virtual Task AuthenticationFailed(AuthenticationFailedContext context) => OnAuthenticationFailed(context);

        /// <summary>
        /// Invoked when a protocol message is first received.
        /// </summary>
        public virtual Task MessageReceived(MessageReceivedContext context) => OnMessageReceived(context);

        /// <summary>
        /// Invoked after the user-password has passed validation and a ClaimsIdentity has been generated.
        /// </summary>
        public virtual Task UserAuthenticated(UserAuthenticatedContext context) => OnUserAuthenticated(context);
    }
}