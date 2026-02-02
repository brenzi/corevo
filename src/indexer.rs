use codec::Decode;
use futures::TryStreamExt;
use mongodb::{bson::{doc, Bson}, options::ClientOptions, Client};
use mongodb::error::Result;
use crate::chain_helpers::decode_hex;
use crate::primitives::{CorevoRemark, PrefixedCorevoRemark};

pub async fn get_history() -> Result<()> {
    // Adjust the URI, database, and collection as needed.
    let uri = "mongodb://readonly:123456@62.84.182.186:27017/?directConnection=true";
    let db_name = "litescan_kusama_assethub";
    let coll_name = "extrinsics";

    let mut client_options = ClientOptions::parse(uri).await?;
    client_options.app_name = Some("corevo-print-remarks".to_string());
    let client = Client::with_options(client_options)?;

    let db = client.database(db_name);
    let coll = db.collection::<mongodb::bson::Document>(coll_name);

    // Query: { method: "remark", "args.remark": { $regex: /^0xcc00ee/i } }
    let filter = doc! {
        "method": "remark",
        "args.remark": { "$regex": "^0xcc00ee", "$options": "i" }
    };

    let mut cursor = coll.find(filter).await?;
    while let Some(doc) = cursor.try_next().await? {
        // Safely navigate to args.remark
        let remark = doc.get_document("args")
            .ok()
            .and_then(|args| args.get("remark"))
            .and_then(|v| match v {
                Bson::String(s) => Some(s.as_str()),
                _ => None,
            });

        if let Some(r) = remark {
            let _ = decode_hex(r)
                .and_then(|remark_bytes| Ok(PrefixedCorevoRemark::decode(&mut remark_bytes.as_slice())
                    .and_then(|pcr| {
                        if let CorevoRemark::V1(cr) = pcr.0 {
                            println!("⛓🗄️ corevo remark: {}", cr);
                        }
                        Ok(())
                    })));
        }
    }
    Ok(())
}