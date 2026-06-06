package com.coldentry.specter;

interface SpecterPromptInvoker {

	default String invoke(String prompt) {
		return invoke(prompt, SpecterStreamingResponseListener.IGNORE);
	}

	String invoke(String prompt, SpecterStreamingResponseListener listener);
}
