use std::{cell::RefCell, rc::Rc, time::Duration};

use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
    future::{Either, select},
};
use worker::{Response, Result, State, WebSocket};
use wormhole_proto::mux::MuxControl;

use super::helpers::{protocol_error, send_mux};
use super::{Runtime, pump_request, websocket_bridge, wire};
use crate::api;

pub(super) struct Context {
    pub(super) runtime: Rc<RefCell<Runtime>>,
    pub(super) ws: WebSocket,
    pub(super) connection: String,
    pub(super) channel: u32,
    pub(super) body: mpsc::Receiver<std::result::Result<Vec<u8>, worker::Error>>,
    pub(super) credits: Option<mpsc::UnboundedReceiver<u32>>,
    pub(super) method: String,
    pub(super) upgrade: bool,
    pub(super) noindex: bool,
}

impl Context {
    pub(super) async fn finish(
        mut self,
        state: &State,
        head_rx: oneshot::Receiver<
            std::result::Result<wormhole_proto::frames::HttpResponseHead, String>,
        >,
        request_body: Option<worker::ByteStream>,
    ) -> Result<Response> {
        if !self.upgrade {
            state.wait_until(pump_request(
                self.ws.clone(),
                self.channel,
                request_body,
                self.credits.take().expect("credit receiver"),
            ));
        }
        let Some(head) = self.wait_for_head(head_rx).await? else {
            return api::index_policy(
                api::error(
                    502,
                    "tunnel_failed",
                    "client did not return response headers within 10 seconds",
                ),
                self.noindex,
            );
        };
        if self.upgrade && head.status == 101 {
            return websocket_bridge::response(
                state,
                websocket_bridge::Upgrade {
                    runtime: self.runtime,
                    control: self.ws,
                    connection: self.connection,
                    channel: self.channel,
                    body: self.body,
                    credits: self.credits.take().expect("credit receiver"),
                },
                &head,
                self.noindex,
            );
        }
        if self.upgrade {
            state.wait_until(pump_request(
                self.ws.clone(),
                self.channel,
                None,
                self.credits.take().expect("credit receiver"),
            ));
        }
        self.regular_response(&head)
    }

    async fn wait_for_head(
        &self,
        head_rx: oneshot::Receiver<
            std::result::Result<wormhole_proto::frames::HttpResponseHead, String>,
        >,
    ) -> Result<Option<wormhole_proto::frames::HttpResponseHead>> {
        match select(Box::pin(head_rx), Box::pin(worker::Delay::from(Duration::from_secs(10))))
            .await
        {
            Either::Left((Ok(Ok(head)), _)) => Ok(Some(head)),
            Either::Left((_, _)) | Either::Right(((), _)) => {
                self.runtime.borrow_mut().pending.remove(&(self.connection.clone(), self.channel));
                let _ignored = send_mux(&self.ws, &MuxControl::Reset { channel: self.channel });
                Ok(None)
            }
        }
    }

    fn regular_response(self, head: &wormhole_proto::frames::HttpResponseHead) -> Result<Response> {
        let headers = wire::response_headers(head, self.noindex).map_err(protocol_error)?;
        let response = if wire::response_allows_body(&self.method, head.status) {
            let response_ws = self.ws.clone();
            let channel = self.channel;
            let body = self.body.map(move |result| {
                let bytes = result?;
                send_mux(
                    &response_ws,
                    &MuxControl::Window {
                        channel,
                        bytes: bytes.len().try_into().unwrap_or(u32::MAX),
                    },
                )?;
                Ok::<Vec<u8>, worker::Error>(bytes)
            });
            Response::from_stream(body)?
        } else {
            drop(self.body);
            Response::empty()?
        }
        .with_status(head.status)
        .with_headers(headers);
        Ok(response.with_encode_body(worker::EncodeBody::Manual))
    }
}
