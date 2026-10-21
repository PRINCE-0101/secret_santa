from fastapi.testclient import TestClient
import main


def test_draw_lock_and_private_giftee_wishlists(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(main, "JWT_SECRET", "integration-test-secret-at-least-32-characters")
    monkeypatch.setattr(main, "ADMIN_INVITE_CODE", "organizer-code")

    with TestClient(main.app) as client:
        organizer = client.post("/auth/signup", json={
            "name": "Organizer", "email": "org@example.com", "password": "organizer-password",
            "organizer_code": "organizer-code",
        }).json()
        duplicate_organizer = client.post("/auth/signup", json={
            "name": "Second Organizer", "email": "org2@example.com", "password": "organizer-password",
            "organizer_code": "organizer-code",
        })
        assert duplicate_organizer.status_code == 409

        people = []
        for name in ["Aanya", "Kabir", "Riya"]:
            result = client.post("/auth/signup", json={
                "name": name, "email": f"{name.lower()}@example.com", "password": "participant-password",
            })
            assert result.status_code == 201
            people.append(result.json())

        org_headers = {"Authorization": f"Bearer {organizer['access_token']}"}
        assert client.post("/draw/run", headers=org_headers).status_code == 200
        assert client.post("/draw/run", headers=org_headers).status_code == 409
        assert client.post("/auth/signup", json={
            "name": "Late", "email": "late@example.com", "password": "participant-password",
        }).status_code == 409

        assignments = {}
        for person in people:
            token = person["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            who = client.get("/my-giftee", headers=headers)
            assert who.status_code == 200
            assignments[person["name"]] = who.json()["giftee"]["name"]
            assert "assignments" not in who.json()

        assert set(assignments) == {"Aanya", "Kabir", "Riya"}
        assert set(assignments.values()) == set(assignments)
        assert all(giver != giftee for giver, giftee in assignments.items())
        assert all(assignments[assignments[giver]] != giver for giver in assignments)

        wishlists = {"Aanya": "A book", "Kabir": "A board game", "Riya": "Tea"}
        for person in people:
            headers = {"Authorization": f"Bearer {person['access_token']}"}
            assert client.put("/my-wishlist", headers=headers, json={"wishlist": wishlists[person['name']]}).status_code == 200
        for person in people:
            headers = {"Authorization": f"Bearer {person['access_token']}"}
            response = client.get("/my-giftee/wishlist", headers=headers)
            giftee_name = assignments[person["name"]]
            assert response.json() == {"giftee_name": giftee_name, "wishlist": wishlists[giftee_name]}

        first_headers = {"Authorization": f"Bearer {people[0]['access_token']}"}
        assert client.post("/auth/logout", headers=first_headers).status_code == 200
        assert client.get("/my-giftee", headers=first_headers).status_code == 401
