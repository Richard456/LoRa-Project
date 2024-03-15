from queue import Queue

from threading import Thread

from requests_futures.sessions import FuturesSession

class WebhookWorker:
    def __init__(self, urls):
        self.urls = urls
        self.session = FuturesSession()
        self.q = Queue()
        self.t = Thread(target=self._consume_thread)
        self.t.start()

    def webhook(self, obj):
        for url in self.urls:
            f = self.session.post(url, json=obj, timeout=5)
            self.q.put(f)

    def terminate(self):
        self.q.put(None)
        self.t.join(3)

    def _consume_thread(self):
        while True:
            future = self.q.get()
            if future is None:
                break
            else:
                try:
                    print(f'webhook status {future.result().status_code}')
                except Exception as e:
                    print(f'Exception with request: {e}')
