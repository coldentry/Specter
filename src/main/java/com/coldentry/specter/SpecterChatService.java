package com.coldentry.specter;

import java.util.List;

interface SpecterChatService {

	SpecterStreamingRequest streamReply(List<SpecterChatMessage> conversation,
			SpecterStreamingResponseListener listener);
}
