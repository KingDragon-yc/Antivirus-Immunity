pub mod toll_like_receptor;

pub trait Receptor {
    fn scan(&self) -> anyhow::Result<()>;
}
