use std::env;
use std::sync::Arc;

use reqwest;
use tokio;
use azure_sdk_auth_aad::*;
use azure_sdk_core::prelude::*;
use azure_sdk_storage_blob::prelude::*;
use azure_sdk_storage_core as azure_storage;
use azure_sdk_storage_core::Client;
use oauth2::{ClientId, ClientSecret};
use std::error::Error;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let client_id = ClientId::new(env::var("AZURE_CLIENT_ID").unwrap());
    let client_secret = ClientSecret::new(
        env::var("AZURE_CLIENT_SECRET").unwrap()
    );
    let tenant_id = env::var("AZURE_TENANT_ID").unwrap();
    let account = env::var("AZURE_STORAGE_ACCOUNT")
        .expect("Missing AZURE_STORAGE_ACCOUNT environment variable.");

    // This Future will give you the final token to
    // use in authorization.
    let client = Arc::new(reqwest::Client::new());
    let token = authorize_client_credentials_flow(
        client.clone(),
        &client_id,
        &client_secret,
        &format!(
            "https://{}.blob.core.windows.net/.default",
            account,
        ),
        &tenant_id,
    )
    .await.unwrap();
    println!("{:?}", token);

    let client = azure_storage::client::with_bearer_token(
        &account,
        token.access_token.secret().to_string(),
    );

    println!("{:?}", client.list_containers().finalize().await?);

        let data = b"1337 azure blob test";
    let (container, blob) = ("test", "test1");
    let mut block_ids = Vec::new();
    for (i, block) in data.chunks(64 * 1024 * 1024 /* 64 MiB */).enumerate() {
        block_ids.push(i.to_be_bytes());
        let digest = md5::compute(block);
        client
            .put_block()
            .with_container_name(container)
            .with_blob_name(blob)
            .with_body(block)
            .with_block_id(&i.to_be_bytes()[..])
            .with_content_md5(&digest[..])
            .finalize()
            .await?;
    }

    let mut block_list = BlockList::default();
    for id in block_ids.iter() {
        block_list.blocks.push(BlobBlockType::Uncommitted(&id[..]));
    }

    client
        .put_block_list()
        .with_container_name(container)
        .with_blob_name(blob)
        .with_block_list(&block_list)
        .finalize()
        .await?;

    Ok(())
}
