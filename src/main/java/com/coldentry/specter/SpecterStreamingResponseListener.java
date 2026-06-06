package com.coldentry.specter;

interface SpecterStreamingResponseListener {

	SpecterStreamingResponseListener IGNORE = new SpecterStreamingResponseListener() {
		@Override
		public void onPartialResponse(String partialResponse) {
			// Ignore streamed content.
		}

		@Override
		public void onPartialThinking(String partialThinking) {
			// Ignore streamed thinking.
		}

		@Override
		public void onToolCall(String toolName, String arguments) {
			// Ignore tool progress.
		}

		@Override
		public void onComplete(SpecterAssistantReply completeResponse) {
			// Ignore completion.
		}

		@Override
		public void onError(Throwable error) {
			// Ignore errors.
		}
	};

	void onPartialResponse(String partialResponse);

	void onPartialThinking(String partialThinking);

	void onToolCall(String toolName, String arguments);

	default void onToolResult(String toolName, String result) {
		// Tool results are optional UI events.
	}

	void onComplete(SpecterAssistantReply completeResponse);

	void onError(Throwable error);
}
