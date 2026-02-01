

litescan mongodb query:
`{method: "remark", "args.remark": { $regex: /^CoReVo:/ }}`


Add or update metadata for different chains
```
cargo install subxt-cli
subxt metadata  --url wss://polkadot-asset-hub-rpc.polkadot.io:443 > polkadot_asset_hub_metadata.scale
subxt metadata  --url wss://sys.ibp.network/asset-hub-kusama:443 > kusama_asset_hub_metadata.scale
subxt metadata  --url wss://sys.ibp.network/asset-hub-paseo:443 > paseo_asset_hub_metadata.scale
subxt metadata  --url wss://collectives-paseo.rpc.amforc.com:443 > paseo_collectives_metadata.scale
```