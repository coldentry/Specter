package com.coldentry.specter;

interface SpecterStreamingRequest {

	SpecterStreamingRequest NO_OP = new SpecterStreamingRequest() {
		@Override
		public void run() {
			// Nothing to do.
		}

		@Override
		public void cancel() {
			// Nothing to cancel.
		}
	};

	void run();

	void cancel();
}
