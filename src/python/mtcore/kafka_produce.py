"""Producer back-pressure for the live pipeline.

confluent_kafka's produce() raises BufferError when the local queue is full
(queue.buffering.max.messages, 100,000 by default); the agents publish a whole
window's rule evaluations at once (~120,000 per PILOT run), which overflowed
it in the Exp. 3 live replay. produce() here serves delivery callbacks until
there is room and then enqueues, so nothing is dropped and nothing is reordered.
"""


def produce(producer, *args, **kwargs):
    while True:
        try:
            producer.produce(*args, **kwargs)
            return
        except BufferError:
            producer.poll(0.1)
