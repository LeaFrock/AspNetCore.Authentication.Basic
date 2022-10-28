using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Authentication.Basic
{
    internal static partial class LoggingExtensions
    {
        [LoggerMessage(1, LogLevel.Information, "Failed to authenticate the user.", EventName = "UserAuthenticatedFailed")]
        public static partial void UserAuthenticatedFailed(this ILogger logger, Exception ex);

        [LoggerMessage(2, LogLevel.Debug, "Successfully authenticate the user.", EventName = "UserAuthenticatedSucceeded")]
        public static partial void UserAuthenticatedSucceeded(this ILogger logger);

        [LoggerMessage(3, LogLevel.Error, "Exception occurred while processing message.", EventName = "ProcessingMessageFailed")]
        public static partial void ErrorProcessingMessage(this ILogger logger, Exception ex);
    }
}