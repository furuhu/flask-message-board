-- schema.sql (更新 Part 11b)
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    content TEXT NOT NULL,
    -- 新增 user_id 欄位，設為 NOT NULL 表示每條訊息都必須有關聯的使用者
    user_id INTEGER NOT NULL,
    -- 設定 user_id 為外鍵，關聯到 users 表的 id 欄位
    FOREIGN KEY (user_id) REFERENCES users (id)
);